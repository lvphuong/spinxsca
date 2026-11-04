//! Sidecar supervision (ADR-048): spawn the local spinxsca service, read its ready handshake,
//! restart it with backoff when it dies or stops answering, and rotate its log.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const MAX_RESTARTS: u32 = 5;
const LOG_LIMIT_BYTES: u64 = 5 * 1024 * 1024;

/// Parses the sidecar's ready line: `SPINXSCA_READY port=<n>`.
pub fn parse_handshake(line: &str) -> Option<u16> {
    let rest = line.trim().strip_prefix("SPINXSCA_READY ")?;
    let port = rest.split_whitespace().find_map(|kv| kv.strip_prefix("port="))?;
    port.parse::<u16>().ok().filter(|p| *p > 0)
}

/// Delay before restart number `attempt` (0-based): 1, 2, 4, 8, 16 seconds; None after the limit.
pub fn backoff(attempt: u32) -> Option<Duration> {
    (attempt < MAX_RESTARTS).then(|| Duration::from_secs(1u64 << attempt))
}

#[derive(Clone, Debug)]
pub struct SidecarSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub log_path: PathBuf,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SidecarState {
    pub running: bool,
    pub restarts: u32,
    pub port: Option<u16>,
}

pub struct Supervisor {
    spec: Mutex<SidecarSpec>,
    child: Mutex<Option<Child>>,
    pub state: Arc<Mutex<SidecarState>>,
}

impl Supervisor {
    pub fn new(spec: SidecarSpec) -> Arc<Self> {
        Arc::new(Self { spec: Mutex::new(spec), child: Mutex::new(None), state: Arc::new(Mutex::new(SidecarState::default())) })
    }

    /// The spec used by the next (re)start.
    pub fn spec_guard(&self) -> std::sync::MutexGuard<'_, SidecarSpec> {
        self.spec.lock().unwrap()
    }

    /// Replaces environment values (e.g. a provider key changed) for the next start.
    pub fn set_env(&self, key: &str, value: Option<String>) {
        let mut spec = self.spec.lock().unwrap();
        match value {
            Some(v) => spec.env.insert(key.to_string(), v),
            None => spec.env.remove(key),
        };
    }

    /// Starts the sidecar and waits for its handshake (port) up to `timeout`.
    pub fn start(self: &Arc<Self>, timeout: Duration) -> Result<u16, String> {
        let spec = self.spec.lock().unwrap().clone();
        rotate_log(&spec.log_path);
        let log = OpenOptions::new().create(true).append(true).open(&spec.log_path).map_err(|e| e.to_string())?;
        let mut command = Command::new(&spec.program);
        command.args(&spec.args).env_clear().envs(&spec.env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::from(log));
        let mut child = command.spawn().map_err(|e| format!("cannot start the local service: {e}"))?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel();
        let log_path = spec.log_path.clone();
        thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if !sent {
                    if let Some(port) = parse_handshake(&line) {
                        let _ = tx.send(port);
                        sent = true;
                        continue;
                    }
                }
                if let Ok(mut f) = OpenOptions::new().append(true).open(&log_path) {
                    let _ = writeln!(f, "{line}");
                }
            }
        });
        *self.child.lock().unwrap() = Some(child);
        let port = rx.recv_timeout(timeout).map_err(|_| "the local service did not report ready in time".to_string())?;
        let mut state = self.state.lock().unwrap();
        state.running = true;
        state.port = Some(port);
        Ok(port)
    }

    /// Watches the process and its health endpoint; restarts with backoff, gives up after MAX_RESTARTS.
    pub fn supervise(self: &Arc<Self>, on_restart: impl Fn(u16) + Send + 'static) {
        let me = Arc::clone(self);
        thread::spawn(move || {
            let mut failures = 0u32;
            loop {
                thread::sleep(Duration::from_secs(5));
                let port = me.state.lock().unwrap().port;
                let exited = me.child.lock().unwrap().as_mut().map(|c| matches!(c.try_wait(), Ok(Some(_)))).unwrap_or(true);
                let healthy = !exited && port.map(health).unwrap_or(false);
                failures = if healthy { 0 } else { failures + 1 };
                if !exited && failures < 3 {
                    continue;
                }
                me.stop();
                let attempt = me.state.lock().unwrap().restarts;
                let Some(delay) = backoff(attempt) else {
                    me.state.lock().unwrap().running = false;
                    return;
                };
                thread::sleep(delay);
                me.state.lock().unwrap().restarts += 1;
                if let Ok(port) = me.start(Duration::from_secs(60)) {
                    failures = 0;
                    on_restart(port);
                }
            }
        });
    }

    pub fn stop(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.state.lock().unwrap().running = false;
    }
}

/// Minimal health probe over loopback (no TLS, no proxies).
fn health(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    if stream.write_all(b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut head = [0u8; 16];
    stream.read(&mut head).map(|n| head[..n].starts_with(b"HTTP/1.1 200")).unwrap_or(false)
}

fn rotate_log(path: &PathBuf) {
    if fs::metadata(path).map(|m| m.len() > LOG_LIMIT_BYTES).unwrap_or(false) {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_ready_line() {
        assert_eq!(parse_handshake("SPINXSCA_READY port=41234"), Some(41234));
        assert_eq!(parse_handshake("  SPINXSCA_READY version=1 port=8080 \n"), Some(8080));
        assert_eq!(parse_handshake("SPINXSCA_READY port=0"), None);
        assert_eq!(parse_handshake("SPINXSCA_READY port=99999"), None);
        assert_eq!(parse_handshake("listening on 127.0.0.1:8080"), None);
    }

    #[test]
    fn backs_off_exponentially_then_gives_up() {
        let delays: Vec<u64> = (0..6).filter_map(backoff).map(|d| d.as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16]);
        assert!(backoff(MAX_RESTARTS).is_none());
    }
}

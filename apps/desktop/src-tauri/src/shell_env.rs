//! Environment of the sidecar: the user's login-shell PATH (GUI apps on macOS start with a bare
//! PATH, so docker and git would not be found) and nothing else inherited by default.

use std::process::Command;

const FALLBACK_DIRS: &[&str] = &[
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/Applications/Docker.app/Contents/Resources/bin",
];

/// PATH reported by the login shell, merged with common tool locations.
pub fn login_path() -> String {
    let mut parts: Vec<String> = Vec::new();
    #[cfg(unix)]
    {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".into());
        if let Ok(out) = Command::new(shell).args(["-ilc", "printf %s \"$PATH\""]).output() {
            if out.status.success() {
                parts.extend(String::from_utf8_lossy(&out.stdout).split(':').filter(|p| p.starts_with('/')).map(String::from));
            }
        }
    }
    if let Ok(current) = std::env::var("PATH") {
        parts.extend(std::env::split_paths(&current).map(|p| p.display().to_string()));
    }
    parts.extend(FALLBACK_DIRS.iter().map(|s| s.to_string()));
    merge(parts)
}

pub fn merge(parts: Vec<String>) -> String {
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = parts.into_iter().filter(|p| !p.is_empty() && seen.insert(p.clone())).collect();
    unique.join(if cfg!(windows) { ";" } else { ":" })
}

#[derive(serde::Serialize)]
pub struct DockerStatus {
    pub available: bool,
    pub version: Option<String>,
    pub detail: String,
}

pub fn docker_status(path: &str) -> DockerStatus {
    match Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]).env("PATH", path).output() {
        Ok(out) if out.status.success() => DockerStatus {
            available: true,
            version: Some(String::from_utf8_lossy(&out.stdout).trim().to_string()),
            detail: "docker daemon reachable".into(),
        },
        Ok(out) => DockerStatus {
            available: false,
            version: None,
            detail: format!("docker is installed but the daemon is not reachable: {}", String::from_utf8_lossy(&out.stderr).trim()),
        },
        Err(_) => DockerStatus { available: false, version: None, detail: "docker was not found; install Docker Desktop or another engine".into() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_without_duplicates_or_empty_entries() {
        let merged = merge(vec!["/a".into(), "".into(), "/b".into(), "/a".into()]);
        assert_eq!(merged, if cfg!(windows) { "/a;/b" } else { "/a:/b" });
    }
}

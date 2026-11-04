//! Spinx SecureCode AI desktop shell (ADR-048): starts and supervises the local spinxsca service as
//! a sidecar, hands its URL and a per-launch token to the webview, keeps provider keys in the OS
//! keychain and lives in the tray. The webview talks to the sidecar over loopback HTTP only.

mod secrets;
mod shell_env;
mod supervisor;
mod token;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use supervisor::{SidecarSpec, SidecarState, Supervisor};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

struct AppState {
    supervisor: Arc<Supervisor>,
    path: String,
}

const DEFAULT_CONFIG: &str = "# Operator configuration of the desktop app (never read from a reviewed repository).
version: 1
ai:
  level: deep
  provider: anthropic
  autonomy:
    mode: supervised
";

#[tauri::command]
fn docker_status(state: tauri::State<'_, AppState>) -> shell_env::DockerStatus {
    shell_env::docker_status(&state.path)
}

#[tauri::command]
fn provider_key_present(provider: String) -> bool {
    secrets::get(&provider).is_some()
}

/// Stores a key and restarts the sidecar so it picks it up; the key never returns to the webview.
#[tauri::command]
fn set_provider_key(state: tauri::State<'_, AppState>, provider: String, key: String) -> Result<(), String> {
    secrets::set(&provider, &key)?;
    if let Some(var) = secrets::env_var(&provider) {
        state.supervisor.set_env(var, Some(key));
        state.supervisor.stop();
    }
    Ok(())
}

#[tauri::command]
fn delete_provider_key(state: tauri::State<'_, AppState>, provider: String) -> Result<(), String> {
    secrets::delete(&provider)?;
    if let Some(var) = secrets::env_var(&provider) {
        state.supervisor.set_env(var, None);
        state.supervisor.stop();
    }
    Ok(())
}

#[tauri::command]
fn sidecar_status(state: tauri::State<'_, AppState>) -> SidecarState {
    state.supervisor.state.lock().unwrap().clone()
}

/// Sidecar program: SPINXSCA_SIDECAR in development ("node /path/apps/cli/dist/index.mjs"), else the
/// bundled Node runtime and CLI in the resources directory.
fn sidecar_command(resources: &Path, data_dir: &Path, port: u16) -> (PathBuf, Vec<String>) {
    let (program, mut args) = match std::env::var("SPINXSCA_SIDECAR") {
        Ok(cmd) if !cmd.trim().is_empty() => {
            let mut parts = cmd.split_whitespace().map(String::from);
            (PathBuf::from(parts.next().unwrap_or_default()), parts.collect::<Vec<_>>())
        }
        _ => {
            let node = if cfg!(windows) { "node.exe" } else { "bin/node" };
            (resources.join("sidecar").join("node").join(node), vec![resources.join("sidecar").join("cli").join("index.mjs").display().to_string()])
        }
    };
    args.extend([
        "serve".into(),
        "--desktop".into(),
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string(),
        "--data-dir".into(),
        data_dir.join("server").display().to_string(),
        "--kb-dir".into(),
        data_dir.join("kb").display().to_string(),
        "--config".into(),
        data_dir.join("spinxsca.yaml").display().to_string(),
    ]);
    (program, args)
}

/// Only what the sidecar needs: PATH from the login shell, the launch token, the parent pid,
/// provider keys from the keychain, and the few variables Docker and Node rely on.
fn sidecar_env(path: &str, token: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("PATH".into(), path.to_string());
    env.insert("SPINXSCA_API_TOKEN".into(), token.to_string());
    env.insert("SPINXSCA_PARENT_PID".into(), std::process::id().to_string());
    for var in ["HOME", "USER", "LANG", "TMPDIR", "TEMP", "TMP", "SystemRoot", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR"] {
        if let Ok(v) = std::env::var(var) {
            env.insert(var.into(), v);
        }
    }
    for provider in ["anthropic", "openai-compatible"] {
        if let (Some(var), Some(key)) = (secrets::env_var(provider), secrets::get(provider)) {
            env.insert(var.into(), key);
        }
    }
    env
}

pub fn run() {
    let token = token::generate_token();
    let app = tauri::Builder::default()
        // First: a second launch focuses the running instance instead of starting another sidecar.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![docker_status, provider_key_present, set_provider_key, delete_provider_key, sidecar_status])
        .setup(move |app| {
            // Updates are signed with minisign; the plugin is enabled once a real public key is configured.
            let updater_ready = app
                .config()
                .plugins
                .0
                .get("updater")
                .and_then(|u| u.get("pubkey"))
                .and_then(|p| p.as_str())
                .is_some_and(|p| !p.starts_with("REPLACE"));
            if updater_ready {
                app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
            }
            let data_dir = app.path().app_data_dir()?;
            fs::create_dir_all(data_dir.join("server"))?;
            let config = data_dir.join("spinxsca.yaml");
            if !config.exists() {
                fs::write(&config, DEFAULT_CONFIG)?;
            }
            let resources = app.path().resource_dir()?;
            let path = shell_env::login_path();
            let (program, args) = sidecar_command(&resources, &data_dir, 0);
            let supervisor = Supervisor::new(SidecarSpec { program, args, env: sidecar_env(&path, &token), log_path: data_dir.join("sidecar.log") });
            let port = match supervisor.start(Duration::from_secs(90)) {
                Ok(port) => {
                    // Restarts keep the same port: the webview's connection is frozen at load.
                    let (program, args) = sidecar_command(&resources, &data_dir, port);
                    let mut spec = SidecarSpec { program, args, env: sidecar_env(&path, &token), log_path: data_dir.join("sidecar.log") };
                    std::mem::swap(&mut *supervisor_spec(&supervisor), &mut spec);
                    port
                }
                Err(err) => {
                    eprintln!("spinxsca sidecar: {err}");
                    0
                }
            };
            supervisor.supervise(|_| {});
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Spinx SecureCode AI")
                .inner_size(1280.0, 840.0)
                .min_inner_size(900.0, 600.0)
                .initialization_script(token::initialization_script(&format!("http://127.0.0.1:{port}"), &token))
                .build()?;
            let open = MenuItem::with_id(app, "open", "Open Spinx", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::new().menu(&menu).tooltip("Spinx SecureCode AI").on_menu_event(|app, event| match event.id().as_ref() {
                "open" => {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
                "quit" => app.exit(0),
                _ => {}
            });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            app.manage(AppState { supervisor, path });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close to tray: reviews keep running; Quit in the tray menu stops everything.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the Spinx desktop app");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<AppState>() {
                state.supervisor.stop();
            }
        }
    });
}

fn supervisor_spec(s: &Arc<Supervisor>) -> std::sync::MutexGuard<'_, SidecarSpec> {
    s.spec_guard()
}

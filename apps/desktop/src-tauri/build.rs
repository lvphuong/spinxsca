fn main() {
    // Only these custom commands can be invoked from the webview; capabilities grant them per window.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "docker_status",
            "provider_key_present",
            "set_provider_key",
            "delete_provider_key",
            "sidecar_status",
            "retry_sidecar",
            "open_sidecar_log",
        ]),
    ))
    .expect("failed to run tauri-build");
}

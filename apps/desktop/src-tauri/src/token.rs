//! Per-launch secret shared by the shell, the sidecar and the webview. Held only in memory.

/// 256-bit random token, hex encoded (64 characters).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS random source unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Script run in the webview before any page script: the sidecar URL and token, frozen.
/// Values are JSON-encoded, so nothing in them can break out of the string literal.
pub fn initialization_script(base_url: &str, token: &str) -> String {
    let conn = serde_json::json!({ "baseUrl": base_url, "token": token });
    format!(
        "Object.defineProperty(window, '__SPINXSCA__', {{ value: Object.freeze({conn}), writable: false, configurable: false }});"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_hex_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn script_escapes_values() {
        let s = initialization_script("http://127.0.0.1:5000", "abc\"; alert(1); //");
        assert!(s.contains(r#""token":"abc\"; alert(1); //""#));
        assert!(s.contains("Object.freeze"));
    }
}

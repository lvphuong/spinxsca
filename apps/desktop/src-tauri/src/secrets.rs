//! Model provider keys in the OS keychain. The webview can store, test for and delete a key, but
//! never read it back; the shell hands it to the sidecar's environment only.

const SERVICE: &str = "com.spinxsca.desktop";

/// Providers and the environment variable the sidecar reads.
pub fn env_var(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        "openai-compatible" => Some("SPINXSCA_LLM_API_KEY"),
        _ => None,
    }
}

fn entry(provider: &str) -> Result<keyring::Entry, String> {
    env_var(provider).ok_or_else(|| format!("unknown provider {provider}"))?;
    keyring::Entry::new(SERVICE, provider).map_err(|e| e.to_string())
}

pub fn get(provider: &str) -> Option<String> {
    entry(provider).ok()?.get_password().ok()
}

pub fn set(provider: &str, key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.len() < 20 || key.len() > 512 || key.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("that does not look like an API key".into());
    }
    entry(provider)?.set_password(key).map_err(|e| e.to_string())
}

pub fn delete(provider: &str) -> Result<(), String> {
    match entry(provider)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_providers() {
        assert_eq!(env_var("anthropic"), Some("ANTHROPIC_API_KEY"));
        assert!(env_var("../../etc").is_none());
        assert!(set("evil", "x".repeat(30).as_str()).is_err());
    }
}

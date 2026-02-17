// Configuration IO — file discovery, loading, and starter config creation.

use std::path::PathBuf;

use crate::types::Config;

/// Find the config file path per R10.
pub fn config_path() -> Option<PathBuf> {
    // 1. $MAYI_CONFIG
    if let Ok(p) = std::env::var("MAYI_CONFIG") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }

    // 2. $XDG_CONFIG_HOME/may-i/config.lisp
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("may-i/config.lisp");
        if path.exists() {
            return Some(path);
        }
    }

    // 3. ~/.config/may-i/config.lisp
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".config/may-i/config.lisp");
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Load config, creating a starter config file if none exists.
pub fn load() -> Result<Config, String> {
    let path = match config_path() {
        Some(path) => path,
        None => {
            let path = default_config_path().ok_or("cannot determine config directory")?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
            }
            std::fs::write(&path, include_str!("starter_config.lisp"))
                .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
            eprintln!("Created starter config at {}", path.display());
            path
        }
    };

    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    crate::config_parse::parse(&content)
}

/// The preferred config path (XDG or ~/.config fallback).
fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/config.lisp"));
    }
    dirs::home_dir().map(|h| h.join(".config/may-i/config.lisp"))
}

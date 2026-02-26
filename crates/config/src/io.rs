// Configuration IO — file discovery, loading, and starter config creation.

use std::path::{Path, PathBuf};

use may_i_core::{LoadError, Config};

/// Find the config file path per R10.
fn config_path() -> Option<PathBuf> {
    // 1. $MAYI_CONFIG
    if let Ok(p) = std::env::var("MAYI_CONFIG") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }

    // 2-3. $XDG_CONFIG_HOME or ~/.config fallback
    default_config_path().filter(|p| p.exists())
}

/// Load config, creating a starter config file if none exists.
///
/// If `override_path` is provided, it takes precedence over `$MAYI_CONFIG`
/// and the default config location.
pub fn load(override_path: Option<&Path>) -> Result<Config, LoadError> {
    let path = match override_path {
        Some(p) => {
            if !p.exists() {
                return Err(LoadError::Io(format!(
                    "Config file not found: {}",
                    p.display()
                )));
            }
            p.to_path_buf()
        }
        None => match config_path() {
            Some(path) => path,
            None => {
                let path =
                    default_config_path().ok_or(LoadError::Io("cannot determine config directory".into()))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        LoadError::Io(format!("Failed to create {}: {e}", parent.display()))
                    })?;
                }
                std::fs::write(&path, include_str!("starter_config.lisp")).map_err(|e| {
                    LoadError::Io(format!("Failed to write {}: {e}", path.display()))
                })?;
                eprintln!("Created starter config at {}", path.display());
                path
            }
        },
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| LoadError::Io(format!("Failed to read {}: {e}", path.display())))?;

    let filename = path.display().to_string();
    crate::parse::parse(&content, &filename).map_err(LoadError::from)
}

/// The preferred config path (XDG or ~/.config fallback).
fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/config.lisp"));
    }
    dirs::home_dir().map(|h| h.join(".config/may-i/config.lisp"))
}

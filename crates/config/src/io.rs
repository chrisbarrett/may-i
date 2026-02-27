// Configuration IO — file discovery, loading, and starter config creation.

use std::path::{Path, PathBuf};

use may_i_core::Config;
use miette::{Context, IntoDiagnostic};

/// Resolve the config file path.
///
/// If `override_path` is provided it takes precedence, then `$MAYI_CONFIG`,
/// then `$XDG_CONFIG_HOME/may-i/config.lisp` or `~/.config/may-i/config.lisp`.
/// Creates a starter config if no file exists at the default location.
pub fn resolve_path(override_path: Option<&Path>) -> miette::Result<PathBuf> {
    match override_path {
        Some(p) => {
            if !p.exists() {
                miette::bail!("Config file not found: {}", p.display());
            }
            Ok(p.to_path_buf())
        }
        None => match env_or_default_path() {
            Some(path) => Ok(path),
            None => {
                let path = default_config_path()
                    .ok_or_else(|| miette::miette!("cannot determine config directory"))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("Failed to create {}", parent.display()))?;
                }
                std::fs::write(&path, include_str!("starter_config.lisp"))
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to write {}", path.display()))?;
                eprintln!("Created starter config at {}", path.display());
                Ok(path)
            }
        },
    }
}

/// Load and parse a config file at the given path.
pub fn load(path: &Path) -> miette::Result<Config> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))?;

    let filename = path.display().to_string();
    crate::parse::parse(&content, &filename).map_err(|e| (*e).into())
}

/// Find an existing config file: `$MAYI_CONFIG` then XDG/default.
fn env_or_default_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MAYI_CONFIG") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    default_config_path().filter(|p| p.exists())
}

/// The preferred config path (XDG or ~/.config fallback).
fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/config.lisp"));
    }
    dirs::home_dir().map(|h| h.join(".config/may-i/config.lisp"))
}

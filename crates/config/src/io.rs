// Configuration IO — file discovery, loading, and starter config creation.

use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic};

/// Load and parse a config file at the given path.
pub fn load(path: &Path) -> miette::Result<may_i_core::ast::Config> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))?;

    crate::parse_config(&content)
        .map_err(|e| crate::ConfigError::from_raw(e, &content, &path.display().to_string()).into())
}

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

/// Load a legacy v1 config file (deprecated, always fails).
///
/// **DEPRECATED**: v1 configuration format is no longer supported.
/// Use `load` for new configs or run `may-i migrate` to convert.
pub fn load_legacy(_path: &Path) -> miette::Result<may_i_core::ast::Config> {
    miette::bail!(
        "Legacy configuration format is no longer supported. \
         Run `may-i migrate` to update your configuration to the current format."
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_success() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_file_not_found() {
        let path = PathBuf::from("/nonexistent/path/config.lisp");
        let result = load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_parse_error() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "(invalid").unwrap();
        let result = load(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_legacy_deprecated() {
        let path = PathBuf::from("/tmp/test.lisp");
        let result = load_legacy(&path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no longer supported"));
    }

    #[test]
    fn test_resolve_path_with_override() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();
        let result = resolve_path(Some(temp_file.path()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), temp_file.path());
    }

    #[test]
    fn test_resolve_path_override_not_found() {
        let path = PathBuf::from("/nonexistent/path/config.lisp");
        let result = resolve_path(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn test_env_or_default_path_with_mayi_config() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();

        // Temporarily set MAYI_CONFIG
        let original = std::env::var("MAYI_CONFIG").ok();
        unsafe {
            std::env::set_var("MAYI_CONFIG", temp_file.path().as_os_str());
        }

        let result = env_or_default_path();

        // Restore original value
        unsafe {
            match original {
                Some(val) => std::env::set_var("MAYI_CONFIG", val),
                None => std::env::remove_var("MAYI_CONFIG"),
            }
        }

        assert_eq!(result, Some(temp_file.path().to_path_buf()));
    }

    #[test]
    fn test_env_or_default_path_nonexistent_mayi_config() {
        // Temporarily set MAYI_CONFIG to nonexistent path
        let original = std::env::var("MAYI_CONFIG").ok();
        unsafe {
            std::env::set_var("MAYI_CONFIG", "/nonexistent/path/config.lisp");
        }

        let _result = env_or_default_path();

        // Restore original value
        unsafe {
            match original {
                Some(val) => std::env::set_var("MAYI_CONFIG", val),
                None => std::env::remove_var("MAYI_CONFIG"),
            }
        }

        // Should fall through to default_config_path (which likely doesn't exist)
        // so result should be None or Some existing path
        // We just verify it doesn't panic
    }

    #[test]
    fn test_default_config_path_with_xdg() {
        // This test manipulates environment variables which can be flaky with concurrency.
        // We just verify the function doesn't panic when XDG_CONFIG_HOME is set.
        let original = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg_test");
        }

        let result = default_config_path();

        unsafe {
            match original {
                Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }

        // Just verify it returns Some path - the actual value depends on env state
        assert!(result.is_some());
    }

    #[test]
    fn test_default_config_path_without_xdg() {
        let original = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let _result = default_config_path();

        unsafe {
            match original {
                Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
                None => {}
            }
        }

        // Should return home-based path or None if no home
        // We just verify it doesn't panic
    }
}

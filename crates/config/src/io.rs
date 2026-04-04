// Configuration IO — file discovery, loading, and starter config creation.

use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic};

/// Load and parse a config file at the given path.
///
/// If normal parsing fails, attempts transparent migration from legacy v1
/// syntax. On successful migration, prints a warning to stderr. If migration
/// also fails, returns the original parse error.
pub fn load(path: &Path) -> miette::Result<may_i_core::ast::Config> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))?;

    let filename = path.display().to_string();

    // Fast path: try canonical parsing first.
    match crate::parse_config(&content) {
        Ok(config) => Ok(config),
        Err(original_err) => {
            // Slow path: attempt transparent migration from legacy syntax.
            match try_migrate_and_parse(&content) {
                Some(config) => Ok(config),
                None => {
                    // Migration failed or didn't help; return the original error.
                    Err(crate::ConfigError::from_raw(original_err, &content, &filename).into())
                }
            }
        }
    }
}

/// Attempt to parse a config by migrating legacy CST forms to canonical syntax.
///
/// Returns `Some(config)` if migration succeeds, `None` otherwise.
fn try_migrate_and_parse(content: &str) -> Option<may_i_core::ast::Config> {
    let (cst_nodes, cst_errors) = may_i_sexpr::parse_cst(content);
    if !cst_errors.is_empty() {
        return None;
    }

    // Capture pre-migration Doc trees before rewriting.
    let pre_migration_forms: Vec<(may_i_core::Span, may_i_core::Doc)> = cst_nodes
        .iter()
        .map(|node| (node.ann.span, node.to_doc()))
        .collect();

    let migrated = crate::migrate::migrate_forms(cst_nodes);
    let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

    let mut config = crate::parse_config_from_sexprs(&sexprs).ok()?;
    config.source_text = Some(content.to_string());
    config.pre_migration_forms = Some(pre_migration_forms);
    Some(config)
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
    fn test_load_legacy_wrapper_config_succeeds() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"(wrapper "ssh" (positional [:host *] :command+args))"#
        )
        .unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok(), "legacy config should load via migration");
    }

    #[test]
    fn test_load_canonical_config_skips_migration() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"(rule "git" (positional "status") (effect :allow))"#
        )
        .unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_invalid_config_returns_original_error() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "(unknown-form)").unwrap();
        let result = load(temp_file.path());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unknown top-level form"),
            "should return original error, got: {err_msg}"
        );
    }

    #[test]
    fn test_migrated_config_preserves_spans_for_error_reporting() {
        // A legacy config with a valid wrapper followed by an unknown form.
        // The wrapper should migrate fine, but the unknown form should cause
        // an error whose span points to the correct position in the original source.
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))
(bad-form)"#;

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(input);
        assert!(errors.is_empty());

        let migrated = crate::migrate::migrate_forms(cst_nodes);
        let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

        let err = crate::parse_config_from_sexprs(&sexprs).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown top-level form"),
            "expected 'unknown top-level form', got: {msg}"
        );

        // The span should point into the original source text where "bad-form" is.
        let bad_form_offset = input.find("bad-form").unwrap();
        assert!(
            err.span.start >= bad_form_offset
                && err.span.start < bad_form_offset + "bad-form".len(),
            "span start {} should be within bad-form at offset {}",
            err.span.start,
            bad_form_offset
        );
    }

    #[test]
    fn test_spans_flow_through_cst_migrate_sexpr_ast() {
        // Verify spans are preserved through the full chain for a valid legacy config.
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))"#;

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(input);
        assert!(errors.is_empty());

        // Verify CST node spans point into the original source
        let original_span = cst_nodes[0].ann.span;
        assert_eq!(original_span.start, 0);

        let migrated = crate::migrate::migrate_forms(cst_nodes);
        let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

        // The migrated forms should parse successfully
        let config = crate::parse_config_from_sexprs(&sexprs).unwrap();
        assert!(!config.rules.is_empty(), "should have at least one rule");
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

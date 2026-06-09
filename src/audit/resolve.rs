// Per-field settings resolution for the Audit log.
//
// Each setting resolves independently with the precedence
// `flag > environment variable > config form > built-in default`. Overriding
// one field must not reset another. CLI/env threshold values are bare strings
// (`ask`); the keyword spelling (`:ask`) is the `(audit …)` form's syntax.

use may_i_core::ast::{AuditConfig, AuditThreshold};
use std::path::PathBuf;

/// The CLI-flag and environment overrides for audit settings. Each is read
/// from its source (clap / `std::env`) by the caller; resolution itself is
/// pure so it is exercised without touching the process environment.
#[derive(Debug, Default, Clone)]
pub struct AuditOverrides {
    /// `--audit-threshold` (bare string).
    pub flag_threshold: Option<String>,
    /// `--audit-file`.
    pub flag_file: Option<String>,
    /// `MAYI_AUDIT_THRESHOLD` (bare string).
    pub env_threshold: Option<String>,
    /// `MAYI_AUDIT_FILE`.
    pub env_file: Option<String>,
}

/// Resolve the effective [`AuditConfig`] from the config form and the
/// CLI/env overrides. Returns an error if a flag- or env-supplied threshold
/// is not one of `off`/`deny`/`ask`/`all`.
pub fn resolve_audit_config(
    form: &AuditConfig,
    overrides: &AuditOverrides,
) -> Result<AuditConfig, String> {
    let threshold = match overrides
        .flag_threshold
        .as_deref()
        .or(overrides.env_threshold.as_deref())
    {
        Some(s) => AuditThreshold::from_bare(s).ok_or_else(|| {
            format!("invalid audit threshold `{s}`: valid values are off, deny, ask, all")
        })?,
        None => form.threshold,
    };

    let file = overrides
        .flag_file
        .clone()
        .or_else(|| overrides.env_file.clone())
        .map(PathBuf::from)
        .or_else(|| form.file.clone());

    Ok(AuditConfig { threshold, file })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(threshold: AuditThreshold, file: Option<&str>) -> AuditConfig {
        AuditConfig {
            threshold,
            file: file.map(PathBuf::from),
        }
    }

    #[test]
    fn flag_overrides_threshold_but_not_file() {
        let cfg = form(AuditThreshold::Ask, Some("/var/x.jsonl"));
        let ov = AuditOverrides {
            flag_threshold: Some("all".to_string()),
            ..Default::default()
        };
        let eff = resolve_audit_config(&cfg, &ov).unwrap();
        assert_eq!(eff.threshold, AuditThreshold::All);
        assert_eq!(
            eff.file.as_deref(),
            Some(std::path::Path::new("/var/x.jsonl"))
        );
    }

    #[test]
    fn env_overrides_form_and_is_overridden_by_flag() {
        let cfg = form(AuditThreshold::Off, None);

        // env alone applies when no flag is given.
        let ov = AuditOverrides {
            env_threshold: Some("ask".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_audit_config(&cfg, &ov).unwrap().threshold,
            AuditThreshold::Ask
        );

        // flag wins over env.
        let ov = AuditOverrides {
            flag_threshold: Some("deny".to_string()),
            env_threshold: Some("ask".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_audit_config(&cfg, &ov).unwrap().threshold,
            AuditThreshold::Deny
        );
    }

    #[test]
    fn file_precedence_flag_env_form() {
        let cfg = form(AuditThreshold::Deny, Some("/form.jsonl"));

        let ov = AuditOverrides {
            env_file: Some("/env.jsonl".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_audit_config(&cfg, &ov).unwrap().file.as_deref(),
            Some(std::path::Path::new("/env.jsonl"))
        );

        let ov = AuditOverrides {
            flag_file: Some("/flag.jsonl".to_string()),
            env_file: Some("/env.jsonl".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_audit_config(&cfg, &ov).unwrap().file.as_deref(),
            Some(std::path::Path::new("/flag.jsonl"))
        );
    }

    #[test]
    fn defaults_when_nothing_set() {
        let eff =
            resolve_audit_config(&AuditConfig::default(), &AuditOverrides::default()).unwrap();
        assert_eq!(eff.threshold, AuditThreshold::Off);
        assert!(eff.file.is_none());
    }

    #[test]
    fn invalid_threshold_is_error() {
        let ov = AuditOverrides {
            flag_threshold: Some("loud".to_string()),
            ..Default::default()
        };
        let err = resolve_audit_config(&AuditConfig::default(), &ov).unwrap_err();
        assert!(err.contains("off, deny, ask, all"), "got: {err}");
    }

    #[test]
    fn env_threshold_enables_no_flag_path() {
        // The no-flag hook path is configurable purely via the environment.
        let ov = AuditOverrides {
            env_threshold: Some("deny".to_string()),
            ..Default::default()
        };
        let eff = resolve_audit_config(&AuditConfig::default(), &ov).unwrap();
        assert_eq!(eff.threshold, AuditThreshold::Deny);
    }
}

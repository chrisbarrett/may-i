// Shared trust advisory logic — computes trust state and renders advisory boxes.
//
// Used by cmd_eval, cmd_check, and cmd_migrate to show consistent trust
// warnings without duplicating the hash computation / store loading dance.

use std::collections::BTreeSet;
use std::path::PathBuf;

use may_i_engine::trust::{canonical_rule, compute_trust_hashes, hash_rule};

use crate::output;
use crate::trust_store::{self, TrustCheck, TrustStatus, TrustStore};

/// An untrusted program entry with its provenance.
pub struct UntrustedEntry {
    pub program: String,
    pub source_files: BTreeSet<PathBuf>,
    pub display_files: Vec<String>,
}

/// Result of computing the trust state for a config.
pub struct TrustState {
    pub untrusted: Vec<UntrustedEntry>,
}

/// Compute trust state: which programs have untrusted loaded rules.
///
/// Returns `None` if there are no loaded rules at all (trust is irrelevant).
pub fn compute(config: &may_i_core::ast::Config) -> Option<TrustState> {
    let hashes = compute_trust_hashes(config);
    if hashes.is_empty() {
        return None;
    }

    let store_path = trust_store::default_trust_store_path()?;
    let load_result = TrustStore::load(&store_path).ok()?;
    let programs = hashes.programs();

    let untrusted: Vec<UntrustedEntry> = programs
        .iter()
        .filter(|(name, meta)| load_result.store.check(name, &meta.hash) != TrustStatus::Trusted)
        .map(|(name, meta)| UntrustedEntry {
            program: name.clone(),
            source_files: meta.source_files.clone(),
            display_files: meta
                .source_files
                .iter()
                .map(|p| output::shorten_home(p))
                .collect(),
        })
        .collect();

    Some(TrustState { untrusted })
}

/// Compute trust state and render all applicable advisory boxes to stderr.
///
/// Handles corrupt store, integrity failures, and untrusted programs.
/// Returns the computed state for callers that need it.
pub fn render(config: &may_i_core::ast::Config, term: &output::Terminal) -> Option<TrustState> {
    let hashes = compute_trust_hashes(config);
    if hashes.is_empty() {
        return None;
    }

    let store_path = trust_store::default_trust_store_path()?;
    let load_result = match TrustStore::load(&store_path) {
        Ok(r) => r,
        Err(_) => {
            let note = output::trust_integrity_note(&store_path, None);
            output::write_layout(&mut std::io::stderr(), &note, term);
            return None;
        }
    };

    // Corrupt file
    if load_result.was_corrupt {
        let note = output::trust_integrity_note(&store_path, None);
        output::write_layout(&mut std::io::stderr(), &note, term);
    }

    // Integrity failures
    if !load_result.suspects.is_empty() {
        let names: Vec<&str> = load_result
            .suspects
            .iter()
            .map(|s| s.program.as_str())
            .collect();
        let note = output::trust_integrity_note(&store_path, Some(&names));
        output::write_layout(&mut std::io::stderr(), &note, term);
    }

    // Untrusted programs
    let programs = hashes.programs();
    let untrusted: Vec<UntrustedEntry> = programs
        .iter()
        .filter(|(name, meta)| load_result.store.check(name, &meta.hash) != TrustStatus::Trusted)
        .map(|(name, meta)| UntrustedEntry {
            program: name.clone(),
            source_files: meta.source_files.clone(),
            display_files: meta
                .source_files
                .iter()
                .map(|p| output::shorten_home(p))
                .collect(),
        })
        .collect();

    if !untrusted.is_empty() {
        let pairs: Vec<(&str, &BTreeSet<PathBuf>)> = untrusted
            .iter()
            .map(|e| (e.program.as_str(), &e.source_files))
            .collect();
        if let Some(note) = output::trust_warning_note(&pairs) {
            output::write_layout(&mut std::io::stderr(), &note, term);
        }
    }

    Some(TrustState { untrusted })
}

/// Filter loaded rules by trust status, removing unapproved ones in place.
///
/// - Primary config rules always pass through.
/// - Loaded rules included only if per-rule hash is approved in store.
/// - Blocked and pending loaded rules are excluded.
pub fn filter_trusted_rules(config: &mut may_i_core::ast::Config, store: &TrustStore) {
    config.rules.retain(|rule| {
        if !rule.provenance.is_loaded() {
            return true;
        }
        let form = canonical_rule(rule);
        let hash = hash_rule(&form);
        store.check_rule(&hash) == TrustCheck::Approved
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Decision;
    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use std::path::PathBuf;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn make_rule(cmd: &str, decision: Decision, provenance: Provenance) -> Rule {
        Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(cmd.into()))),
            effect: spanned(Effect::Terminal {
                decision,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance,
        }
    }

    fn make_config(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            defines: vec![],
            security: may_i_core::ast::SecurityConfig::default(),
            checks: vec![],
        }
    }

    #[test]
    fn filter_keeps_primary_rules() {
        let mut config = make_config(vec![make_rule(
            "ls",
            Decision::Allow,
            Provenance::PrimaryConfig,
        )]);
        let store = TrustStore::default(); // empty store
        filter_trusted_rules(&mut config, &store);
        assert_eq!(config.rules.len(), 1, "primary rule should remain");
    }

    #[test]
    fn filter_removes_pending_loaded_rules() {
        let mut config = make_config(vec![make_rule(
            "git",
            Decision::Allow,
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        )]);
        let store = TrustStore::default(); // empty = all pending
        filter_trusted_rules(&mut config, &store);
        assert!(
            config.rules.is_empty(),
            "pending loaded rule should be removed"
        );
    }

    #[test]
    fn filter_keeps_approved_loaded_rules() {
        let loaded_rule = make_rule(
            "git",
            Decision::Allow,
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );
        let form = canonical_rule(&loaded_rule);
        let hash = hash_rule(&form);

        let mut store = TrustStore::default();
        store.approve_rule(hash, "git".into(), form);

        let mut config = make_config(vec![loaded_rule]);
        filter_trusted_rules(&mut config, &store);
        assert_eq!(config.rules.len(), 1, "approved loaded rule should remain");
    }

    #[test]
    fn filter_removes_blocked_loaded_rules() {
        let loaded_rule = make_rule(
            "git",
            Decision::Allow,
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );
        let form = canonical_rule(&loaded_rule);
        let hash = hash_rule(&form);

        let mut store = TrustStore::default();
        store.block_rule(hash, "git".into(), form);

        let mut config = make_config(vec![loaded_rule]);
        filter_trusted_rules(&mut config, &store);
        assert!(
            config.rules.is_empty(),
            "blocked loaded rule should be removed"
        );
    }

    #[test]
    fn filter_mixed_rules() {
        let primary = make_rule("ls", Decision::Allow, Provenance::PrimaryConfig);
        let approved_rule = make_rule(
            "git",
            Decision::Allow,
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );
        let pending_rule = make_rule(
            "rm",
            Decision::Deny,
            Provenance::Loaded {
                path: PathBuf::from("test"),
            },
        );

        let form = canonical_rule(&approved_rule);
        let hash = hash_rule(&form);
        let mut store = TrustStore::default();
        store.approve_rule(hash, "git".into(), form);

        let mut config = make_config(vec![primary, approved_rule, pending_rule]);
        filter_trusted_rules(&mut config, &store);
        assert_eq!(
            config.rules.len(),
            2,
            "primary + approved should remain, pending removed"
        );
    }
}

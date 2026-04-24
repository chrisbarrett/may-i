// Shared trust advisory logic — computes trust state and renders advisory boxes.
//
// Used by cmd_eval, cmd_check, and cmd_migrate to show consistent trust
// warnings without duplicating the hash computation / store loading dance.

use std::collections::BTreeSet;
use std::path::PathBuf;

use may_i_engine::trust::compute_trust_hashes;

use crate::output;
use crate::trust_store::{self, TrustStatus, TrustStore};

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
    if hashes.programs.is_empty() {
        return None;
    }

    let store_path = trust_store::default_trust_store_path()?;
    let load_result = TrustStore::load(&store_path).ok()?;

    let untrusted: Vec<UntrustedEntry> = hashes
        .programs
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
    if hashes.programs.is_empty() {
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
    let untrusted: Vec<UntrustedEntry> = hashes
        .programs
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

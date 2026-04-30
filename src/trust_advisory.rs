// Shared trust advisory logic — computes trust state and renders advisory boxes.
//
// Used by cmd_eval, cmd_check, and cmd_migrate to show consistent trust
// warnings without duplicating the hash computation / store loading dance.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use colored::Colorize;
use may_i_engine::trust::{canonical_rule, compute_trust_hashes, hash_rule};
use may_i_layout::{Advisory, ColItem, Layout, NoteLevel};

use crate::output;
use crate::trust_store::{self, TrustCheck, TrustStatus, TrustStore};

/// An untrusted program entry with its provenance.
pub struct UntrustedEntry {
    program: String,
    source_files: BTreeSet<PathBuf>,
    display_files: Vec<String>,
}

impl UntrustedEntry {
    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn display_files(&self) -> &[String] {
        &self.display_files
    }
}

/// Result of computing the trust state for a config.
pub struct TrustState {
    untrusted: Vec<UntrustedEntry>,
}

impl TrustState {
    pub fn untrusted(&self) -> &[UntrustedEntry] {
        &self.untrusted
    }
}

/// Compute trust state: which programs have untrusted loaded rules.
///
/// Returns `None` if there are no loaded rules at all (trust is irrelevant).
pub(crate) fn compute(config: &may_i_core::ast::Config) -> Option<TrustState> {
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

/// Build a trust warning advisory layout for untrusted programs in `config`.
///
/// Returns `None` if there are no loaded rules, no trust store available,
/// or no untrusted programs.
pub fn build_warning_layout(config: &may_i_core::ast::Config) -> Option<Layout> {
    let state = compute(config)?;
    build_warning_layout_from_entries(&state.untrusted)
}

fn build_warning_layout_from_entries(entries: &[UntrustedEntry]) -> Option<Layout> {
    if entries.is_empty() {
        return None;
    }

    // Group programs by source file.
    let mut file_to_programs: std::collections::BTreeMap<&Path, Vec<&str>> =
        std::collections::BTreeMap::new();
    for entry in entries {
        if entry.source_files.is_empty() {
            file_to_programs
                .entry(Path::new("<unknown>"))
                .or_default()
                .push(entry.program.as_str());
        } else {
            for file in &entry.source_files {
                file_to_programs
                    .entry(file.as_path())
                    .or_default()
                    .push(entry.program.as_str());
            }
        }
    }

    let child = trust_samples(&file_to_programs);

    Some(
        Advisory {
            level: NoteLevel::Warn,
            heading: "Untrusted rules".into(),
            detail: "Rules from these files need approval before they take effect.".into(),
            suggestion: "Review and approve by running:".into(),
            command: "may-i trust".into(),
            children: vec![child],
        }
        .into_layout(),
    )
}

/// Build a trust store integrity error layout.
///
/// If `suspect_names` is `Some`, lists the affected entry names.
/// If `None`, indicates the whole file is corrupt.
pub(crate) fn build_integrity_layout(store_path: &Path, suspect_names: Option<&[&str]>) -> Layout {
    let display_path = output::shorten_home(store_path);

    match suspect_names {
        Some(names) => {
            let name_list = format_name_list(names.iter().copied(), names.len());
            Advisory {
                level: NoteLevel::Error,
                heading: "Trust store integrity failure".into(),
                detail: format!(
                    "{} entries in {} have mismatched hashes: {name_list}.",
                    names.len(),
                    display_path,
                ),
                suggestion: "This may indicate tampering. Resolve by running:".into(),
                command: "may-i trust".into(),
                children: vec![],
            }
            .into_layout()
        }
        None => Advisory {
            level: NoteLevel::Error,
            heading: "Trust store corrupted".into(),
            detail: format!(
                "{display_path} could not be loaded. The file may be corrupted or tampered. \
                 All programs will require re-approval."
            ),
            suggestion: String::new(),
            command: String::new(),
            children: vec![],
        }
        .into_layout(),
    }
}

/// Build a layout showing per-file trust samples.
///
/// Each entry shows the file path (teal) with count, and up to 5 sample
/// command names that wrap at terminal width.
fn trust_samples(file_to_programs: &std::collections::BTreeMap<&Path, Vec<&str>>) -> Layout {
    let mut children: Vec<Layout> = Vec::new();
    for (file, progs) in file_to_programs {
        let path = output::shorten_home(file);
        let count = progs.len();
        let header = format!("{} ({count})", path.cyan());
        children.push(Layout::Text(header));

        let take = progs.len().min(5);
        let mut items: Vec<ColItem> = progs[..take]
            .iter()
            .map(|p| ColItem::new(*p, p.len()))
            .collect();
        if progs.len() > 5 {
            items.push(ColItem::new("...", 3));
        }
        let sep_text = format!("{} ", ",".dimmed());
        children.push(Layout::Indent(
            3,
            Box::new(Layout::Wrap {
                items,
                separator: ColItem::new(sep_text, 2),
            }),
        ));
    }
    Layout::Stack(children)
}

/// Format a list of names with take-5 truncation.
fn format_name_list<'a>(names: impl Iterator<Item = &'a str>, total: usize) -> String {
    let shown: Vec<&str> = names.take(5).collect();
    let mut result = shown.join(", ");
    if total > 5 {
        result.push_str(&format!(" (and {} more)", total - 5));
    }
    result
}

/// Write trust store integrity advisories to stderr if any apply.
///
/// Handles corrupt-store and per-entry hash-mismatch cases.
/// Skipped silently if the config has no loaded rules or the store path is
/// unavailable.
pub fn write_integrity_advisories(config: &may_i_core::ast::Config, term: &output::Terminal) {
    let hashes = compute_trust_hashes(config);
    if hashes.is_empty() {
        return;
    }

    let Some(store_path) = trust_store::default_trust_store_path() else {
        return;
    };

    let load_result = match TrustStore::load(&store_path) {
        Ok(r) => r,
        Err(_) => {
            let layout = build_integrity_layout(&store_path, None);
            output::write_layout(&mut std::io::stderr(), &layout, term);
            return;
        }
    };

    if load_result.was_corrupt {
        let layout = build_integrity_layout(&store_path, None);
        output::write_layout(&mut std::io::stderr(), &layout, term);
    }

    if !load_result.suspects.is_empty() {
        let names: Vec<&str> = load_result
            .suspects
            .iter()
            .map(|s| s.program.as_str())
            .collect();
        let layout = build_integrity_layout(&store_path, Some(&names));
        output::write_layout(&mut std::io::stderr(), &layout, term);
    }
}

/// Filter loaded rules by trust status, removing unapproved ones in place.
///
/// - Primary config rules always pass through.
/// - Loaded rules included only if per-rule hash is approved in store.
/// - Blocked and pending loaded rules are excluded.
pub(crate) fn filter_trusted_rules(config: &mut may_i_core::ast::Config, store: &TrustStore) {
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
            ..Config::default()
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

    // ── Advisory layout content tests ────────────────────────────────

    fn render_text(layout: &Layout) -> String {
        let term = output::Terminal::new(60);
        let mut buf = Vec::new();
        output::write_layout(&mut buf, layout, &term);
        let raw = String::from_utf8(buf).unwrap();
        may_i_layout::strip_ansi(&raw)
    }

    fn entry(program: &str, files: &[&str]) -> UntrustedEntry {
        let source_files: BTreeSet<PathBuf> = files.iter().map(PathBuf::from).collect();
        let display_files = files.iter().map(|s| (*s).to_string()).collect();
        UntrustedEntry {
            program: program.into(),
            source_files,
            display_files,
        }
    }

    #[test]
    fn warning_layout_empty_returns_none() {
        assert!(build_warning_layout_from_entries(&[]).is_none());
    }

    #[test]
    fn warning_layout_single_program() {
        let entries = vec![entry("git", &["/tmp/rules.lisp"])];
        let layout = build_warning_layout_from_entries(&entries).unwrap();
        let output = render_text(&layout);
        assert!(output.contains("Untrusted rules"), "{output}");
        assert!(output.contains("/tmp/rules.lisp (1)"), "{output}");
        assert!(output.contains("git"), "{output}");
        assert!(output.contains("may-i trust"), "{output}");
    }

    #[test]
    fn warning_layout_multiple_programs_same_file() {
        let entries = vec![
            entry("git", &["/tmp/rules.lisp"]),
            entry("cargo", &["/tmp/rules.lisp"]),
            entry("npm", &["/tmp/rules.lisp"]),
        ];
        let layout = build_warning_layout_from_entries(&entries).unwrap();
        let output = render_text(&layout);
        assert!(output.contains("Untrusted rules"), "{output}");
        assert!(output.contains("/tmp/rules.lisp (3)"), "{output}");
        assert!(output.contains("git"), "{output}");
        assert!(output.contains("cargo"), "{output}");
        assert!(output.contains("npm"), "{output}");
    }

    #[test]
    fn warning_layout_truncates_over_five_programs() {
        let entries: Vec<UntrustedEntry> = (1..=7)
            .map(|i| entry(&format!("cmd{i}"), &["/tmp/rules.lisp"]))
            .collect();
        let layout = build_warning_layout_from_entries(&entries).unwrap();
        let output = render_text(&layout);
        assert!(output.contains("/tmp/rules.lisp (7)"), "{output}");
        assert!(
            output.contains("cmd1, cmd2, cmd3, cmd4, cmd5, ..."),
            "{output}"
        );
        assert!(!output.contains("cmd6"), "{output}");
    }

    #[test]
    fn warning_layout_multiple_files() {
        let entries = vec![
            entry("git", &["/tmp/a.lisp"]),
            entry("npm", &["/tmp/b.lisp"]),
        ];
        let layout = build_warning_layout_from_entries(&entries).unwrap();
        let output = render_text(&layout);
        assert!(output.contains("/tmp/a.lisp"), "{output}");
        assert!(output.contains("/tmp/b.lisp"), "{output}");
    }

    #[test]
    fn integrity_layout_specific_entries() {
        let path = Path::new("/tmp/trust.json");
        let names = ["git", "cargo", "npm"];
        let layout = build_integrity_layout(path, Some(&names));
        let output = render_text(&layout);
        assert!(output.contains("Trust store integrity failure"), "{output}");
        assert!(output.contains("/tmp/trust.json"), "{output}");
        assert!(output.contains("git"), "{output}");
        assert!(output.contains("cargo"), "{output}");
        assert!(output.contains("npm"), "{output}");
        assert!(output.contains("may-i trust"), "{output}");
    }

    #[test]
    fn integrity_layout_truncates_over_five() {
        let path = Path::new("/tmp/trust.json");
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"];
        let layout = build_integrity_layout(path, Some(&names));
        let output = render_text(&layout);
        assert!(output.contains("(and 7 more)"), "{output}");
    }

    #[test]
    fn integrity_layout_corrupt_file() {
        let path = Path::new("/tmp/trust.json");
        let layout = build_integrity_layout(path, None);
        let output = render_text(&layout);
        assert!(output.contains("Trust store corrupted"), "{output}");
        assert!(output.contains("/tmp/trust.json"), "{output}");
        assert!(output.contains("re-approval"), "{output}");
    }

    #[test]
    fn format_name_list_under_five() {
        let result = format_name_list(["a", "b", "c"].iter().copied(), 3);
        assert_eq!(result, "a, b, c");
    }

    #[test]
    fn format_name_list_over_five() {
        let names = ["a", "b", "c", "d", "e", "f", "g"];
        let result = format_name_list(names.iter().copied(), 7);
        assert_eq!(result, "a, b, c, d, e (and 2 more)");
    }
}

// Shared trust advisory logic — derives advisory entries from a TrustCatalog
// and renders integrity / warning advisory boxes.
//
// Used by cmd_eval, cmd_check, and cmd_migrate to show consistent trust
// warnings without duplicating the join between engine metadata and the
// trust store. The join itself lives in `crate::trust::view`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use colored::Colorize;
use may_i_engine::trust::{canonical_rule, hash_rule};
use may_i_output::{Advisory, ColItem, Layout, NoteLevel};

use crate::output;
use crate::trust::view::{TrustCatalog, TrustState};

/// An untrusted program entry with its provenance.
pub(crate) struct UntrustedEntry {
    program: String,
    source_files: BTreeSet<PathBuf>,
    display_files: Vec<String>,
}

impl UntrustedEntry {
    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn display_files(&self) -> &[String] {
        &self.display_files
    }
}

/// Collect the set of untrusted programs from the catalog. Returns
/// program-name-ordered entries, each with the deduplicated set of source
/// files contributed by its untrusted views.
pub(crate) fn untrusted_entries(catalog: &TrustCatalog) -> Vec<UntrustedEntry> {
    let mut by_program: BTreeMap<&str, BTreeSet<PathBuf>> = BTreeMap::new();
    for view in catalog.untrusted_loaded() {
        let entry = by_program.entry(view.program()).or_default();
        if let Some(p) = view.source_file() {
            entry.insert(p.to_path_buf());
        }
    }

    by_program
        .into_iter()
        .map(|(program, source_files)| {
            let display_files = source_files
                .iter()
                .map(|p| output::shorten_home(p))
                .collect();
            UntrustedEntry {
                program: program.to_string(),
                source_files,
                display_files,
            }
        })
        .collect()
}

/// Build a trust warning advisory layout from a catalog. Returns `None`
/// when the catalog is empty or contains no untrusted views.
pub(crate) fn build_warning_layout(catalog: &TrustCatalog) -> Option<Layout> {
    if catalog.is_empty() {
        return None;
    }
    let entries = untrusted_entries(catalog);
    build_warning_layout_from_entries(&entries)
}

fn build_warning_layout_from_entries(entries: &[UntrustedEntry]) -> Option<Layout> {
    if entries.is_empty() {
        return None;
    }

    // Group programs by source file.
    let mut file_to_programs: BTreeMap<&Path, Vec<&str>> = BTreeMap::new();
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
fn trust_samples(file_to_programs: &BTreeMap<&Path, Vec<&str>>) -> Layout {
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

/// Filter loaded rules by approval state, removing unapproved ones in place.
///
/// - Primary config rules always pass through.
/// - Loaded rules included only if their hash is `Approved` in the catalog.
/// - Blocked and pending loaded rules are excluded.
pub(crate) fn filter_trusted_rules(config: &mut may_i_core::ast::Config, catalog: &TrustCatalog) {
    let approved: BTreeSet<&str> = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Approved)
        .map(|v| v.hash())
        .collect();
    config.rules.retain(|rule| {
        if !rule.provenance.is_loaded() {
            return true;
        }
        let form = canonical_rule(rule);
        let hash = hash_rule(&form);
        approved.contains(hash.as_str())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::store::TrustStore;
    use crate::trust::view::build_catalog;
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
        let cat = build_catalog(&config, TrustStore::default());
        filter_trusted_rules(&mut config, &cat);
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
        let cat = build_catalog(&config, TrustStore::default());
        filter_trusted_rules(&mut config, &cat);
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
        let cat = build_catalog(&config, store);
        filter_trusted_rules(&mut config, &cat);
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
        let cat = build_catalog(&config, store);
        filter_trusted_rules(&mut config, &cat);
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
        let cat = build_catalog(&config, store);
        filter_trusted_rules(&mut config, &cat);
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
        may_i_output::strip_ansi(&raw)
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

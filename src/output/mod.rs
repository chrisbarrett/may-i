// Shared display helpers for trace output.
//
// Trace-specific rendering built on top of the `may_i_layout` crate's
// declarative Layout primitives.

mod annotate;
mod colorize;
mod json;
mod render_rule;
mod transform;

#[cfg(test)]
mod test_helpers;

use std::io::Write;

use colored::Colorize;
use may_i_pp::colorize_atom;

pub use may_i_layout::{
    Advisory, ColAlign, ColContent, ColItem, ColRow, HRuleLabel, Layout, Note, NoteLevel, Terminal,
    strip_ansi, write_layout,
};

pub use self::colorize::colorize_decision_keyword;
pub use self::json::trace_to_json;

use self::colorize::colorize_right;
use self::render_rule::render_annotated_rule;
use crate::annotation::TraceEntry;

// ── Advisory notes ────────────────────────────────────────────────

/// Build a migration advisory note if the config was transparently migrated.
pub fn migration_note(
    loaded: &crate::loaded_config::LoadedConfig,
    config_path: &std::path::Path,
) -> Option<Layout> {
    use may_i_layout::NoteHeading;

    if loaded.pre_migration_forms.is_some() {
        let prog = std::env::args()
            .next()
            .map(|s| {
                std::path::Path::new(&s)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or(s)
            })
            .unwrap_or_else(|| "may-i".into());
        let display_path = shorten_home(config_path);
        let prefix = "Migrations available:";
        let heading = NoteHeading {
            text: format!("{} {}", prefix.yellow().bold(), display_path.bold(),),
            visible_width: prefix.len() + 1 + display_path.len(),
        };
        Some(
            Advisory {
                level: NoteLevel::Warn,
                heading: String::new(), // unused — overridden below
                detail: "Your config uses an older syntax that has been automatically \
                     translated. Trace output reflects the translated rules, which \
                     may not match the file on disk."
                    .into(),
                suggestion: "Apply pending migrations by running:".into(),
                command: format!("{prog} migrate"),
                children: vec![],
            }
            .into_note_with_heading(heading),
        )
    } else {
        None
    }
}

/// Build a trust warning advisory note for untrusted programs.
///
/// Returns `None` if the list is empty. Shows a per-file summary with
/// sampled command names inside the advisory box.
pub fn trust_warning_note(
    programs: &[(&str, &std::collections::BTreeSet<std::path::PathBuf>)],
) -> Option<Layout> {
    if programs.is_empty() {
        return None;
    }

    // Group programs by source file.
    let mut file_to_programs: std::collections::BTreeMap<&std::path::Path, Vec<&str>> =
        std::collections::BTreeMap::new();
    for (name, files) in programs {
        if files.is_empty() {
            file_to_programs
                .entry(std::path::Path::new("<unknown>"))
                .or_default()
                .push(name);
        } else {
            for file in *files {
                file_to_programs
                    .entry(file.as_path())
                    .or_default()
                    .push(name);
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

/// Build a layout showing per-file trust samples.
///
/// Each entry shows the file path (teal) with count, and up to 5 sample
/// command names that wrap at terminal width.
fn trust_samples(
    file_to_programs: &std::collections::BTreeMap<&std::path::Path, Vec<&str>>,
) -> Layout {
    let mut children: Vec<Layout> = Vec::new();
    for (file, progs) in file_to_programs {
        let path = shorten_home(file);
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

/// Build a trust store integrity error note.
///
/// If `suspect_names` is `Some`, lists the affected entry names.
/// If `None`, indicates the whole file is corrupt.
pub fn trust_integrity_note(
    store_path: &std::path::Path,
    suspect_names: Option<&[&str]>,
) -> Layout {
    let display_path = shorten_home(store_path);

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

/// Format a list of names with take-5 truncation.
fn format_name_list<'a>(names: impl Iterator<Item = &'a str>, total: usize) -> String {
    let shown: Vec<&str> = names.take(5).collect();
    let mut result = shown.join(", ");
    if total > 5 {
        result.push_str(&format!(" (and {} more)", total - 5));
    }
    result
}

// ── Column geometry (trace-specific) ──────────────────────────────

const MIN_TERM_WIDTH: usize = 40;

struct ColumnGeometry {
    left_width: usize,
}

fn detect_column_geometry(term: &Terminal) -> ColumnGeometry {
    let usable = term.width.saturating_sub(2).max(MIN_TERM_WIDTH);
    ColumnGeometry {
        left_width: usable / 2,
    }
}

// ── Facts rows (2-column layout) ──────────────────────────────────

fn facts_rows(facts: &[(String, String)]) -> Vec<ColRow> {
    let items: Vec<ColItem> = facts
        .iter()
        .map(|(key, value)| {
            let quoted = format!("\"{value}\"");
            let colored = format!(
                "{} {}",
                colorize_atom(key, true),
                colorize_atom(&quoted, true)
            );
            let width = key.len() + 1 + quoted.len();
            ColItem::new(colored, width)
        })
        .collect();

    let label = "facts";
    vec![ColRow {
        left: label.dimmed().to_string(),
        left_width: label.len(),
        left_align: ColAlign::Right,
        right: ColContent::Breakable {
            items,
            separator: ", ".dimmed().to_string(),
            separator_width: 2,
        },
    }]
}

fn command_row(cmd: &str, _geom: &ColumnGeometry) -> Vec<ColRow> {
    let label = "command";
    let label_colored = label.dimmed().to_string();
    let mut row = ColRow::new(label_colored, label.len(), cmd.bold().to_string());
    row.left_align = ColAlign::Right;
    vec![row]
}

// ── Separator (public convenience for cmd_check) ──────────────────

pub(crate) fn print_separator(indent: &str, label: Option<(&str, usize)>, term: &Terminal) {
    let hrule_label = label.map(|(text, w)| HRuleLabel {
        text: text.to_string(),
        visible_width: w,
    });
    let layout = Layout::HRule(hrule_label);
    let indented = Layout::Indent(indent.len(), Box::new(layout));
    write_layout(&mut std::io::stdout(), &indented, term);
}

// ── Public convenience for cmd_check ──────────────────────────────

pub(crate) fn render_elements(indent: &str, elements: &[Layout], term: &Terminal) {
    let layout = Layout::Indent(indent.len(), Box::new(Layout::Stack(elements.to_vec())));
    write_layout(&mut std::io::stdout(), &layout, term);
}

// ── Trace rendering ────────────────────────────────────────────────

pub fn print_trace(entries: &[TraceEntry], command: &str, indent: &str, term: &Terminal) {
    write_trace(&mut std::io::stdout(), entries, command, indent, term);
}

pub fn write_trace(
    w: &mut impl Write,
    entries: &[TraceEntry],
    command: &str,
    indent: &str,
    term: &Terminal,
) {
    let layout = trace_to_layout(entries, command, indent.len(), term);
    write_layout(w, &layout, term);
}

/// Convert trace entries into a declarative layout tree.
fn trace_to_layout(
    entries: &[TraceEntry],
    command: &str,
    indent: usize,
    term: &Terminal,
) -> Layout {
    let geom = detect_column_geometry(term);
    let mut children: Vec<Layout> = Vec::new();
    let mut first = true;

    let has_segments = entries
        .iter()
        .any(|e| matches!(e, TraceEntry::SegmentHeader { .. }));

    let mut pending_command: Option<&str> = if !has_segments { Some(command) } else { None };

    let mut current_rows: Vec<ColRow> = Vec::new();
    let mut last_shown_facts: Option<&Vec<(String, String)>> = None;

    let flush_rows = |rows: &mut Vec<ColRow>, children: &mut Vec<Layout>| {
        if !rows.is_empty() {
            children.push(Layout::Columns(std::mem::take(rows)));
        }
    };

    for entry in entries {
        match entry {
            TraceEntry::SegmentHeader { command, decision } => {
                flush_rows(&mut current_rows, &mut children);
                if !first {
                    children.push(Layout::Blank);
                    children.push(Layout::Blank);
                }
                children.push(segment_header_layout(command, *decision));
                pending_command = Some(command);
            }
            TraceEntry::Rule {
                doc,
                line,
                pre_migration_doc: _,
                facts,
                inner_command,
            } => {
                if inner_command.is_some() || pending_command.is_some() {
                    flush_rows(&mut current_rows, &mut children);
                    last_shown_facts = None;
                    if !first {
                        children.push(Layout::Blank);
                    }
                } else if !current_rows.is_empty() {
                    current_rows.push(ColRow::new(" ", 1, ""));
                }

                if let Some(cmd) = pending_command.take() {
                    current_rows.extend(command_row(cmd, &geom));
                } else if let Some(cmd) = inner_command {
                    current_rows.extend(command_row(cmd, &geom));
                }
                if !facts.is_empty() && last_shown_facts.as_ref() != Some(&facts) {
                    current_rows.extend(facts_rows(facts));
                }
                last_shown_facts = Some(facts);
                current_rows.extend(render_annotated_rule(doc, *line, &geom));
            }
            TraceEntry::EmbeddedCommand { source, decision } => {
                let decision_str = format!(":{decision}");
                let label = format!("{} {}", "embedded:".dimmed(), source.italic());
                let label_visible = "embedded: ".len() + source.len();
                let right = colorize_right(&format!("→ {decision_str}"));
                let mut row = ColRow::new(label, label_visible, right);
                row.left_align = ColAlign::Right;
                current_rows.push(row);
            }
            TraceEntry::DefaultAsk { .. } => {
                let label = "No matching rule".italic().yellow().to_string();
                let label_visible = "No matching rule".len();
                let mut row = ColRow::new(label, label_visible, colorize_right("→ :ask (default)"));
                row.left_align = ColAlign::Right;
                current_rows.push(row);
            }
            TraceEntry::ParseDiagnostics { diagnostics } => {
                for diag in diagnostics {
                    let severity_str = match diag.severity {
                        may_i_shell_parser::Severity::Error => "error".red().bold().to_string(),
                        may_i_shell_parser::Severity::Warning => {
                            "warning".yellow().bold().to_string()
                        }
                    };
                    let msg = diag.message();
                    let label = format!("parse {severity_str}: {msg}");
                    let label_visible = "parse ".len()
                        + match diag.severity {
                            may_i_shell_parser::Severity::Error => "error".len(),
                            may_i_shell_parser::Severity::Warning => "warning".len(),
                        }
                        + ": ".len()
                        + msg.len();
                    let mut row = ColRow::new(label, label_visible, "");
                    row.left_align = ColAlign::Right;
                    current_rows.push(row);
                }
            }
        }
        first = false;
    }
    flush_rows(&mut current_rows, &mut children);

    Layout::Indent(indent, Box::new(Layout::Stack(children)))
}

fn segment_header_layout(command: &str, decision: may_i_core::Decision) -> Layout {
    use may_i_core::Decision;
    let icon = match decision {
        Decision::Allow => "✓".green().bold().to_string(),
        Decision::Ask => "?".yellow().bold().to_string(),
        Decision::Deny => "✗".red().bold().to_string(),
    };
    let label = format!("{icon} {}", command.bold());
    let label_width = 2 + command.len();
    Layout::HRule(Some(HRuleLabel {
        text: label,
        visible_width: label_width,
    }))
}

// ── Path display ───────────────────────────────────────────────────

pub fn shorten_home(path: &std::path::Path) -> String {
    if let Ok(home) = std::env::var("HOME")
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn facts_rows_creates_breakable_row() {
        let facts = vec![
            (":env".to_string(), "prod".to_string()),
            (":region".to_string(), "us-east".to_string()),
        ];
        let rows = facts_rows(&facts);
        assert_eq!(rows.len(), 1);
        let stripped = strip_ansi(&rows[0].left);
        assert_eq!(stripped, "facts");
    }

    #[test]
    fn command_row_creates_row() {
        let geom = ColumnGeometry { left_width: 40 };
        let rows = command_row("git push", &geom);
        assert_eq!(rows.len(), 1);
        let stripped = strip_ansi(&rows[0].left);
        assert_eq!(stripped, "command");
    }

    #[test]
    fn trace_to_layout_empty() {
        let term = Terminal::new(80);
        let layout = trace_to_layout(&[], "ls", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
    }

    #[test]
    fn trace_to_layout_with_default_ask() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "no rules".into(),
        }];
        let layout = trace_to_layout(&entries, "unknown", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("No matching rule"));
    }

    #[test]
    fn trace_to_layout_with_segment_header() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::SegmentHeader {
            command: "ls".into(),
            decision: may_i_core::Decision::Allow,
        }];
        let layout = trace_to_layout(&entries, "ls && echo done", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("ls"));
    }

    #[test]
    fn write_trace_produces_output() {
        let term = Terminal::new(80);
        let entries = vec![TraceEntry::DefaultAsk {
            reason: "test".into(),
        }];
        let mut buf = Vec::new();
        write_trace(&mut buf, &entries, "cmd", "  ", &term);
        assert!(!buf.is_empty());
    }

    #[test]
    fn shorten_home_replaces_home_prefix() {
        if let Ok(home) = std::env::var("HOME") {
            let path = std::path::PathBuf::from(&home).join("foo/bar");
            assert_eq!(shorten_home(&path), "~/foo/bar");
        }
    }

    #[test]
    fn shorten_home_preserves_non_home_path() {
        let path = std::path::Path::new("/tmp/other");
        assert_eq!(shorten_home(path), "/tmp/other");
    }

    #[test]
    fn trace_to_layout_with_rule() {
        let term = Terminal::new(80);
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(3),
            },
            vec![
                atom("rule"),
                atom_ann("git", Ann::CommandMatch { matched: true }),
                atom_ann(
                    ":allow",
                    Ann::EffectDecision {
                        decision: may_i_core::Decision::Allow,
                        reason: Some("ok".into()),
                    },
                ),
            ],
        );
        let entries = vec![TraceEntry::Rule {
            doc,
            line: Some(3),
            pre_migration_doc: None,
            facts: vec![(":env".into(), "prod".into())],
            inner_command: None,
        }];
        let layout = trace_to_layout(&entries, "git push", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("command"));
        assert!(stripped.contains("git push"));
    }

    #[test]
    fn trace_to_layout_with_inner_command() {
        let term = Terminal::new(80);
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule"), atom("rm")],
        );
        let entries = vec![
            TraceEntry::Rule {
                doc: doc.clone(),
                line: Some(1),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: None,
            },
            TraceEntry::Rule {
                doc,
                line: Some(2),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: Some("rm -rf".into()),
            },
        ];
        let layout = trace_to_layout(&entries, "sudo rm -rf", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("rm -rf"));
    }

    #[test]
    fn trace_to_layout_consecutive_rules_get_separator() {
        let term = Terminal::new(80);
        let make_rule = |cmd: &str| TraceEntry::Rule {
            doc: list_ann(
                Ann::RuleMatch {
                    matched: false,
                    line: None,
                },
                vec![atom("rule"), atom(cmd)],
            ),
            line: None,
            pre_migration_doc: None,
            facts: vec![],
            inner_command: None,
        };
        let entries = vec![make_rule("git"), make_rule("hg")];
        let layout = trace_to_layout(&entries, "ls", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        assert!(!buf.is_empty());
    }

    #[test]
    fn trace_to_layout_skips_duplicate_facts() {
        let term = Terminal::new(80);
        let facts = vec![(":env".into(), "prod".into())];
        let make_rule = || TraceEntry::Rule {
            doc: list_ann(
                Ann::RuleMatch {
                    matched: false,
                    line: None,
                },
                vec![atom("rule"), atom("cmd")],
            ),
            line: None,
            pre_migration_doc: None,
            facts: facts.clone(),
            inner_command: None,
        };
        let entries = vec![make_rule(), make_rule()];
        let layout = trace_to_layout(&entries, "cmd", 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        let output = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&output);
        assert_eq!(
            stripped.matches("facts").count(),
            1,
            "facts should appear once: {stripped}"
        );
    }

    #[test]
    fn segment_header_layout_variants() {
        use may_i_core::Decision;
        for decision in [Decision::Allow, Decision::Ask, Decision::Deny] {
            let layout = segment_header_layout("cmd", decision);
            let term = Terminal::new(80);
            let mut buf = Vec::new();
            write_layout(&mut buf, &layout, &term);
            assert!(!buf.is_empty());
        }
    }

    // ── trust_warning_note tests ─────────────────────────────────

    fn render_note(layout: &Layout) -> String {
        let term = Terminal::new(60);
        let mut buf = Vec::new();
        write_layout(&mut buf, layout, &term);
        let output = String::from_utf8(buf).unwrap();
        strip_ansi(&output)
    }

    #[test]
    fn trust_warning_note_empty_returns_none() {
        assert!(trust_warning_note(&[]).is_none());
    }

    #[test]
    fn trust_warning_note_single_program() {
        let mut files = std::collections::BTreeSet::new();
        files.insert(std::path::PathBuf::from("/tmp/rules.lisp"));
        let layout = trust_warning_note(&[("git", &files)]).unwrap();
        let output = render_note(&layout);
        assert!(output.contains("Untrusted rules"), "{output}");
        assert!(
            output.contains("/tmp/rules.lisp (1)"),
            "should show file with count: {output}"
        );
        assert!(
            output.contains("git"),
            "should show sampled command: {output}"
        );
        assert!(output.contains("may-i trust"), "{output}");
    }

    #[test]
    fn trust_warning_note_multiple_programs_same_file() {
        let mut files = std::collections::BTreeSet::new();
        files.insert(std::path::PathBuf::from("/tmp/rules.lisp"));
        let programs: Vec<(&str, &std::collections::BTreeSet<std::path::PathBuf>)> =
            vec![("git", &files), ("cargo", &files), ("npm", &files)];
        let layout = trust_warning_note(&programs).unwrap();
        let output = render_note(&layout);
        assert!(output.contains("Untrusted rules"), "{output}");
        assert!(
            output.contains("/tmp/rules.lisp (3)"),
            "should show file with count: {output}"
        );
        assert!(output.contains("git"), "{output}");
        assert!(output.contains("cargo"), "{output}");
        assert!(output.contains("npm"), "{output}");
        assert!(output.contains("may-i trust"), "{output}");
    }

    #[test]
    fn trust_warning_note_truncates_over_five_programs() {
        let mut files = std::collections::BTreeSet::new();
        files.insert(std::path::PathBuf::from("/tmp/rules.lisp"));
        let programs: Vec<(&str, &std::collections::BTreeSet<std::path::PathBuf>)> = vec![
            ("cmd1", &files),
            ("cmd2", &files),
            ("cmd3", &files),
            ("cmd4", &files),
            ("cmd5", &files),
            ("cmd6", &files),
            ("cmd7", &files),
        ];
        let layout = trust_warning_note(&programs).unwrap();
        let output = render_note(&layout);
        assert!(
            output.contains("/tmp/rules.lisp (7)"),
            "should show count: {output}"
        );
        assert!(
            output.contains("cmd1, cmd2, cmd3, cmd4, cmd5, ..."),
            "should ellipsize after 5: {output}"
        );
        assert!(
            !output.contains("cmd6"),
            "should not show 6th program: {output}"
        );
    }

    #[test]
    fn trust_warning_note_multiple_files() {
        let mut files_a = std::collections::BTreeSet::new();
        files_a.insert(std::path::PathBuf::from("/tmp/a.lisp"));
        let mut files_b = std::collections::BTreeSet::new();
        files_b.insert(std::path::PathBuf::from("/tmp/b.lisp"));
        let programs: Vec<(&str, &std::collections::BTreeSet<std::path::PathBuf>)> =
            vec![("git", &files_a), ("npm", &files_b)];
        let layout = trust_warning_note(&programs).unwrap();
        let output = render_note(&layout);
        assert!(output.contains("/tmp/a.lisp"), "{output}");
        assert!(output.contains("/tmp/b.lisp"), "{output}");
    }

    // ── trust_integrity_note tests ───────────────────────────────

    #[test]
    fn trust_integrity_note_specific_entries() {
        let path = std::path::Path::new("/tmp/trust.json");
        let names = ["git", "cargo", "npm"];
        let layout = trust_integrity_note(path, Some(&names));
        let output = render_note(&layout);
        assert!(output.contains("Trust store integrity failure"), "{output}");
        assert!(output.contains("/tmp/trust.json"), "{output}");
        assert!(output.contains("git"), "{output}");
        assert!(output.contains("cargo"), "{output}");
        assert!(output.contains("npm"), "{output}");
        assert!(output.contains("may-i trust"), "{output}");
    }

    #[test]
    fn trust_integrity_note_truncates_over_five() {
        let path = std::path::Path::new("/tmp/trust.json");
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"];
        let layout = trust_integrity_note(path, Some(&names));
        let output = render_note(&layout);
        assert!(output.contains("(and 7 more)"), "{output}");
    }

    #[test]
    fn trust_integrity_note_corrupt_file() {
        let path = std::path::Path::new("/tmp/trust.json");
        let layout = trust_integrity_note(path, None);
        let output = render_note(&layout);
        assert!(output.contains("Trust store corrupted"), "{output}");
        assert!(output.contains("/tmp/trust.json"), "{output}");
        assert!(output.contains("re-approval"), "{output}");
    }

    // ── format_name_list tests ───────────────────────────────────

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

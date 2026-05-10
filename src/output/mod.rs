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
    // Parser rows pending placement under their command row, keyed by the
    // bare command name recorded with each `TraceEntry::Parser`. Inner
    // evaluations also push parser entries; only those whose command name
    // matches a subsequently-rendered command row are consumed.
    let mut pending_parsers: std::collections::HashMap<String, ColRow> =
        std::collections::HashMap::new();

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
                combine_role: _,
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

                let pushed_cmd: Option<&str> = if let Some(cmd) = pending_command.take() {
                    current_rows.extend(command_row(cmd, &geom));
                    Some(cmd)
                } else if let Some(cmd) = inner_command.as_deref() {
                    current_rows.extend(command_row(cmd, &geom));
                    Some(cmd)
                } else {
                    None
                };
                if let Some(cmd) = pushed_cmd
                    && let Some(first_token) = cmd.split_whitespace().next()
                    && let Some(parser_row) = pending_parsers.remove(first_token)
                {
                    current_rows.push(parser_row);
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
            TraceEntry::Parser {
                command,
                style,
                parameter_tokens,
                tail,
            } => {
                let mut value = style.clone();
                if !parameter_tokens.is_empty() {
                    value.push_str(&format!("  parameters ({})", parameter_tokens.join(" ")));
                }
                if let Some(t) = tail {
                    value.push_str(&format!("  tail {t}"));
                }
                let label = "parser";
                let mut row = ColRow::new(label.dimmed().to_string(), label.len(), value);
                row.left_align = ColAlign::Right;
                pending_parsers.insert(command.clone(), row);
                continue;
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
            combine_role: None,
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
                combine_role: None,
            },
            TraceEntry::Rule {
                doc,
                line: Some(2),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: Some("rm -rf".into()),
                combine_role: None,
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
            combine_role: None,
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
            combine_role: None,
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

    fn render_trace(entries: &[TraceEntry], command: &str) -> String {
        let term = Terminal::new(120);
        let layout = trace_to_layout(entries, command, 0, &term);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &term);
        strip_ansi(&String::from_utf8(buf).unwrap())
    }

    fn parser_then_rule(parameter_tokens: Vec<String>, tail: Option<String>) -> Vec<TraceEntry> {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule"), atom("cmd")],
        );
        vec![
            TraceEntry::Parser {
                command: "cmd".into(),
                style: "gnu".into(),
                parameter_tokens,
                tail,
            },
            TraceEntry::Rule {
                doc,
                line: Some(1),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: None,
                combine_role: None,
            },
        ]
    }

    fn find_row_with(stripped: &str, label: &str) -> Option<(usize, String)> {
        stripped.lines().enumerate().find_map(|(i, l)| {
            // A kv row contains "<label> │"; ensure label is its own token.
            let trimmed = l.trim_start();
            trimmed.split_once('│').and_then(|(left, _)| {
                if left.trim_end().split_whitespace().last() == Some(label) {
                    Some((i, l.to_string()))
                } else {
                    None
                }
            })
        })
    }

    #[test]
    fn parser_row_renders_directly_under_command_no_blank_line() {
        let entries = parser_then_rule(vec![], None);
        let out = render_trace(&entries, "cmd");
        let (cmd_idx, _) = find_row_with(&out, "command").expect("command row missing");
        let (parser_idx, parser_line) = find_row_with(&out, "parser").expect("parser row missing");
        assert_eq!(
            parser_idx,
            cmd_idx + 1,
            "parser must immediately follow command\n--- output ---\n{out}\n---"
        );
        assert!(
            parser_line
                .split_once('│')
                .is_some_and(|(_, r)| r.trim() == "gnu"),
            "parser right column wrong: {parser_line}"
        );
    }

    #[test]
    fn parser_row_with_parameters() {
        let entries = parser_then_rule(vec!["-X".into(), "--request".into()], None);
        let out = render_trace(&entries, "cmd");
        assert!(
            out.contains("gnu  parameters (-X --request)"),
            "right column missing parameters segment:\n{out}"
        );
    }

    #[test]
    fn parser_row_with_tail() {
        let entries = parser_then_rule(vec![], Some("(after :flags)".into()));
        let out = render_trace(&entries, "cmd");
        assert!(
            out.contains("gnu  tail (after :flags)"),
            "right column missing tail segment:\n{out}"
        );
    }

    #[test]
    fn parser_row_with_parameters_and_tail() {
        let entries = parser_then_rule(vec!["-c".into()], Some(r#"(after "--")"#.into()));
        let out = render_trace(&entries, "cmd");
        assert!(
            out.contains(r#"gnu  parameters (-c)  tail (after "--")"#),
            "right column missing combined segments:\n{out}"
        );
    }

    #[test]
    fn inner_parser_entry_does_not_displace_outer_parser_row() {
        // When a rule's effect recurses and the inner evaluation also
        // records a parser, the outer command's parser must still be the
        // one rendered under the outer command row.
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: Some(1),
            },
            vec![atom("rule"), atom("nix")],
        );
        let entries = vec![
            TraceEntry::Parser {
                command: "nix".into(),
                style: "gnu".into(),
                parameter_tokens: vec![],
                tail: Some("(after :flags)".into()),
            },
            TraceEntry::Parser {
                command: "run".into(),
                style: "gnu".into(),
                parameter_tokens: vec![],
                tail: None,
            },
            TraceEntry::DefaultAsk {
                reason: "no rule".into(),
            },
            TraceEntry::Rule {
                doc,
                line: Some(1),
                pre_migration_doc: None,
                facts: vec![],
                inner_command: None,
                combine_role: None,
            },
        ];
        let out = render_trace(&entries, "nix run nixpkgs#hello");
        let (_, parser_line) = find_row_with(&out, "parser").expect("parser row missing");
        assert!(
            parser_line.contains("gnu  tail (after :flags)"),
            "expected outer (nix) parser to be rendered, got: {parser_line}\nfull:\n{out}"
        );
    }

    #[test]
    fn no_full_width_parser_banner() {
        let entries = parser_then_rule(vec![], None);
        let out = render_trace(&entries, "cmd");
        for line in out.lines() {
            assert!(
                !line.trim_start().starts_with("parser:"),
                "found legacy 'parser:' banner row: {line}"
            );
        }
    }

    fn evaluate_trace(config_text: &str, command: &str) -> String {
        use crate::annotation::TracingFold;
        use may_i_core::ContextFacts;
        let config = may_i_config::parse_config(config_text).expect("parse config");
        let facts = ContextFacts::default();
        let mut fold = TracingFold::new();
        may_i_engine::eval::evaluate_command_with_fold(command, &config, &facts, &mut fold)
            .expect("evaluate");
        render_trace(&fold.traces, command)
    }

    #[test]
    fn tail_authorise_annotates_with_tail_slice_single_token() {
        let cfg = r#"
(parser "direnv" (style gnu) (tail (after "exec")))
(rule "direnv" (tail (authorise)))
"#;
        let out = evaluate_trace(cfg, "direnv exec true");
        assert!(
            out.contains("tail = \"true\""),
            "expected `tail = \"true\"` in trace output:\n{out}"
        );
    }

    #[test]
    fn tail_authorise_annotates_with_tail_slice_multi_token() {
        let cfg = r#"
(parser "direnv" (style gnu) (tail (after "exec")))
(rule "direnv" (tail (authorise)))
"#;
        let out = evaluate_trace(cfg, "direnv exec echo hi there");
        assert!(
            out.contains("tail = \"echo hi there\""),
            "expected `tail = \"echo hi there\"` in trace output:\n{out}"
        );
    }

    #[test]
    fn parameter_authorise_annotates_with_captured_value_single() {
        let cfg = r#"
(rule "bash" (parameter "c" (authorise)))
"#;
        let out = evaluate_trace(cfg, "bash -c \"echo hi\"");
        assert!(
            out.contains("value = \"echo hi\""),
            "expected `value = \"echo hi\"` in trace output:\n{out}"
        );
    }

    #[test]
    fn parameter_authorise_annotates_with_captured_value_multi() {
        let cfg = r#"
(rule "bash" (parameter "c" (authorise)))
"#;
        let out = evaluate_trace(cfg, "bash -c \"echo hi there\"");
        assert!(
            out.contains("value = \"echo hi there\""),
            "expected `value = \"echo hi there\"` in trace output:\n{out}"
        );
    }
}

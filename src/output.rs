// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::{Doc, DocF, EvalAnn, TraceEntry};
use may_i_pp::{Format, colorize_atom, pretty, visible_len};

// ── Layout geometry ────────────────────────────────────────────────

/// Minimum usable terminal width before we stop trying to fit two columns.
const MIN_TERM_WIDTH: usize = 40;

/// Unicode box-drawing character used as a column divider.
const DIVIDER: &str = "│";

/// Layout parameters derived from the terminal width.
struct Layout {
    /// Maximum visible width for the left (s-expression) column.
    left_width: usize,
}

fn detect_layout() -> Layout {
    let term_width = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80);
    let usable = term_width.saturating_sub(2).max(MIN_TERM_WIDTH);
    let left_width = usable / 2;
    Layout { left_width }
}

// ── Document types ─────────────────────────────────────────────────

/// A row in a two-column table with a vertical bar divider.
pub struct Row {
    /// Left column content (may contain ANSI codes).
    pub left: String,
    /// Visible width of left column (excluding ANSI).
    pub left_visible: usize,
    /// Right column content (colorized at render time unless pre-colored).
    pub right: String,
    /// If true, the right column is already colorized.
    pub right_precolored: bool,
}

impl Row {
    /// Create a row with auto-colorized right column (trace style).
    pub fn trace(left: impl Into<String>, left_visible: usize, right: impl Into<String>) -> Self {
        Self { left: left.into(), left_visible, right: right.into(), right_precolored: false }
    }

    /// Create a row with a pre-colorized right column (KV style).
    pub fn kv(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let len = key.len();
        Self { left: key, left_visible: len, right: value.into(), right_precolored: true }
    }

    fn is_elision(&self) -> bool {
        self.left_visible == 1 && self.left.contains('…')
    }
}

/// A rendered document element.
pub enum Element {
    /// Empty line.
    Blank,
    /// Full-width horizontal rule with optional label.
    Separator {
        label: Option<(String, usize)>,
    },
    /// A group of rows sharing a divider column.
    Table(Vec<Row>),
}

// ── Rendering ──────────────────────────────────────────────────────

/// Render a sequence of elements with the given indent prefix.
pub fn render_elements(indent: &str, elements: &[Element]) {
    for element in elements {
        match element {
            Element::Blank => println!(),
            Element::Separator { label } => {
                print_separator(indent, label.as_ref().map(|(s, w)| (s.as_str(), *w)));
            }
            Element::Table(rows) => {
                let divider_col = compute_divider_col(rows);
                for row in rows {
                    print_row(indent, row, divider_col);
                }
            }
        }
    }
}

fn compute_divider_col(rows: &[Row]) -> usize {
    let max_left = rows.iter()
        .filter(|r| !r.is_elision())
        .map(|r| r.left_visible)
        .max()
        .unwrap_or(0);
    max_left + 2
}

fn print_row(indent: &str, row: &Row, divider_col: usize) {
    if row.left.is_empty() && row.right.is_empty() {
        return;
    }

    let left_pad = divider_col.saturating_sub(row.left_visible);

    if row.right.is_empty() {
        println!(
            "{indent}{}{:pad$}{}",
            row.left, "", DIVIDER.dimmed(),
            pad = left_pad,
        );
    } else {
        let right = if row.right_precolored {
            row.right.clone()
        } else {
            colorize_right(&row.right)
        };
        println!(
            "{indent}{}{:pad$}{} {}",
            row.left, "", DIVIDER.dimmed(), right,
            pad = left_pad,
        );
    }
}

// ── Separator ──────────────────────────────────────────────────────

/// Print a full-width horizontal rule, optionally embedding a label.
pub fn print_separator(indent: &str, label: Option<(&str, usize)>) {
    let term_width = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80);
    let usable = term_width.saturating_sub(indent.len());

    match label {
        Some((colored_label, label_width)) => {
            let prefix = "─── ";
            let mid = " ";
            let used = visible_len(prefix) + label_width + visible_len(mid);
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            println!(
                "{indent}{}{}{}{}",
                prefix.dimmed(),
                colored_label,
                mid.dimmed(),
                suffix.dimmed(),
            );
        }
        None => {
            let rule = "─".repeat(usable);
            println!("{indent}{}", rule.dimmed());
        }
    }
}

// ── Trace rendering ────────────────────────────────────────────────

/// Render a trace as two-column output: left = rule structure, right = eval.
pub fn print_trace(entries: &[TraceEntry], indent: &str) {
    let layout = detect_layout();
    let mut elements: Vec<Element> = Vec::new();
    let mut first = true;

    for entry in entries {
        match entry {
            TraceEntry::SegmentHeader { command, decision } => {
                if !first {
                    elements.push(Element::Blank);
                    elements.push(Element::Blank);
                }
                elements.push(segment_header_element(command, *decision));
            }
            TraceEntry::Rule { doc, line } => {
                if !first {
                    elements.push(Element::Blank);
                }
                let rows = render_annotated_rule(doc, *line, &layout);
                if !rows.is_empty() {
                    elements.push(Element::Table(rows));
                }
            }
            TraceEntry::DefaultAsk { .. } => {
                let label = "No matching rule".italic().yellow().to_string();
                let label_visible = "No matching rule".len();
                let padded_visible = layout.left_width;
                let pad = padded_visible.saturating_sub(label_visible);
                let left = format!("{:pad$}{label}", "");
                let row = Row::trace(left, padded_visible, "→ :ask (default)");
                // Append to the previous table if possible, else new table.
                if let Some(Element::Table(rows)) = elements.last_mut() {
                    rows.push(row);
                } else {
                    elements.push(Element::Table(vec![row]));
                }
            }
        }
        first = false;
    }

    render_elements(indent, &elements);
}

fn segment_header_element(command: &str, decision: may_i_core::Decision) -> Element {
    use may_i_core::Decision;
    let icon = match decision {
        Decision::Allow => "✓".green().bold().to_string(),
        Decision::Ask => "?".yellow().bold().to_string(),
        Decision::Deny => "✗".red().bold().to_string(),
    };
    let label = format!("{icon} {}", command.bold());
    let label_width = 2 + command.len();
    Element::Separator { label: Some((label, label_width)) }
}

// ── Annotated Doc renderer ─────────────────────────────────────────

/// Render an annotated rule Doc into two-column rows.
fn render_annotated_rule(
    doc: &Doc<Option<EvalAnn>>,
    line: Option<usize>,
    layout: &Layout,
) -> Vec<Row> {
    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: line,
    };
    let rendered = pretty(doc, 0, &fmt);

    // Collect annotations in tree-walk order.
    let annotations = collect_annotations(doc);

    // Find the outcome (RuleEffect on the top-level node).
    let outcome = extract_outcome(doc);
    let matched = has_args_match(doc);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let stripped_lines: Vec<String> = rendered_lines.iter().map(|l| strip_ansi(l)).collect();

    // Forward-scan: match each annotation to a rendered line.
    let mut line_annotations: Vec<String> = vec![String::new(); rendered_lines.len()];
    let mut overflow: Vec<String> = Vec::new();
    let mut search_from = 0;

    for (needle, right_text) in &annotations {
        if needle.is_empty() {
            overflow.push(right_text.clone());
        } else if let Some(idx) = find_line(&stripped_lines, needle, &mut search_from) {
            line_annotations[idx] = right_text.clone();
        } else {
            overflow.push(right_text.clone());
        }
    }

    // Build rows from rendered lines with aligned annotations.
    let mut rows: Vec<Row> = rendered_lines.iter().enumerate().map(|(i, sline)| {
        Row::trace(sline.to_string(), visible_len(sline), line_annotations[i].clone())
    }).collect();

    // Overflow annotations.
    for ann in &overflow {
        rows.push(Row::trace("", 0, ann.clone()));
    }

    // Append outcome on the last line or a new line.
    if let Some(out) = outcome
        && matched
    {
        rows.push(Row::trace("", 0, out));
    }

    rows
}

/// Collect (search_needle, right_column_text) pairs from annotated Doc nodes.
fn collect_annotations(doc: &Doc<Option<EvalAnn>>) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_annotations_inner(doc, &mut result);
    result
}

fn collect_annotations_inner(doc: &Doc<Option<EvalAnn>>, out: &mut Vec<(String, String)>) {
    if let Some(ann) = &doc.ann
        && let Some(pair) = format_annotation(doc, ann)
    {
        out.push(pair);
    }
    if let DocF::List(children) = &doc.node {
        for child in children {
            collect_annotations_inner(child, out);
        }
    }
}

/// Format an annotation into (search_needle, right_column_text).
/// Returns None for annotations that don't produce right-column output.
fn format_annotation(doc: &Doc<Option<EvalAnn>>, ann: &EvalAnn) -> Option<(String, String)> {
    match ann {
        EvalAnn::CommandMatch(_) => None,
        EvalAnn::ArgsResult(_) => None,
        EvalAnn::RuleEffect { .. } => None, // handled as outcome
        EvalAnn::DefaultAsk => None,

        EvalAnn::ExprVsArg { arg, matched } => {
            let needle = node_text(doc);
            let op = if is_regex_node(doc) { "~" } else { "=" };
            let arrow = if *matched { "→ yes" } else { "→ no" };
            let right = format!("{arg} {op} {needle} {arrow}");
            Some((needle, right))
        }
        EvalAnn::Quantifier { count, matched } => {
            let needle = node_text(doc);
            if *matched {
                Some((needle, format!("{count} matched → yes")))
            } else {
                Some((needle, "→ no".into()))
            }
        }
        EvalAnn::Missing => {
            Some((node_text(doc), "→ missing".into()))
        }
        EvalAnn::Anywhere { args, matched } => {
            let pattern = node_text(doc);
            let truncated = truncate_list(args, 4);
            let arrow = if *matched { "→ yes" } else { "→ no" };
            Some((pattern.clone(), format!("{pattern} ∈ {{{truncated}}} {arrow}")))
        }
        EvalAnn::CondBranch { decision } => {
            let needle = node_text(doc);
            Some((needle, format!("→ :{decision}")))
        }
        EvalAnn::CondElse { decision } => {
            Some(("else".into(), format!("→ :{decision}")))
        }
        EvalAnn::ExactRemainder { count } => {
            Some((String::new(), format!("{count} extra args")))
        }
    }
}

/// Get the plain text of a Doc node (for search needle matching).
fn node_text(doc: &Doc<Option<EvalAnn>>) -> String {
    doc.fold(&|node, _ann: &Option<EvalAnn>| match node {
        DocF::Atom(s) => s,
        DocF::List(cs) => format!("({})", cs.join(" ")),
    })
}

/// Check if a Doc node is a regex form like `(regex "...")`.
fn is_regex_node(doc: &Doc<Option<EvalAnn>>) -> bool {
    doc.head_atom() == Some("regex")
}

/// Extract the rule-level outcome annotation.
fn extract_outcome(doc: &Doc<Option<EvalAnn>>) -> Option<String> {
    match &doc.ann {
        Some(EvalAnn::RuleEffect { decision, reason }) => {
            Some(match reason {
                Some(r) => format!("→ :{decision} \"{r}\""),
                None => format!("→ :{decision}"),
            })
        }
        _ => None,
    }
}

/// Check if the rule's args matched (look for ArgsResult(true) annotation).
fn has_args_match(doc: &Doc<Option<EvalAnn>>) -> bool {
    doc.fold(&|node, ann: &Option<EvalAnn>| {
        if matches!(ann, Some(EvalAnn::ArgsResult(true))) {
            return true;
        }
        // If no ArgsResult at all and there's a RuleEffect, it's a simple rule (always matched).
        if matches!(ann, Some(EvalAnn::RuleEffect { .. })) {
            return true;
        }
        match node {
            DocF::List(children) => children.iter().any(|c| *c),
            DocF::Atom(_) => false,
        }
    })
}

/// Forward-scan stripped lines for a needle, advancing the search position.
fn find_line(stripped_lines: &[String], needle: &str, search_from: &mut usize) -> Option<usize> {
    // Try exact substring match.
    for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
        if line.contains(needle) {
            *search_from = i + 1;
            return Some(i);
        }
    }
    // For long needles the pp may have broken across lines; try first token.
    let first_token = needle.split_whitespace().next().unwrap_or(needle);
    if first_token != needle && first_token.len() >= 2 {
        for (i, line) in stripped_lines.iter().enumerate().skip(*search_from) {
            if line.contains(first_token) {
                *search_from = i + 1;
                return Some(i);
            }
        }
    }
    None
}

/// Strip ANSI SGR escape codes from a string.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' { in_escape = false; }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            result.push(ch);
        }
    }
    result
}

/// Truncate a list for display, keeping first few and last.
fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let mut parts: Vec<&str> = items[..2].iter().map(|s| s.as_str()).collect();
        parts.push("…");
        parts.push(items.last().unwrap());
        parts.join(", ")
    }
}

// ── Right-column colorization ──────────────────────────────────────

/// Colorize the right column (evaluation results).
fn colorize_right(s: &str) -> String {
    if s.starts_with("(effect ") || s.starts_with("(default ") {
        return colorize_effect_sexpr(s);
    }

    // Split at "→" to colorize the result portion.
    if let Some(arrow_pos) = s.find("→") {
        let before = &s[..arrow_pos];
        let after = s[arrow_pos + "→".len()..].trim();
        let colored_result = match after {
            "yes" => "yes".green().bold().to_string(),
            "no" => "no".yellow().to_string(),
            "missing" => "missing".yellow().to_string(),
            other if other.starts_with(':') => {
                if let Some(space) = other.find(' ') {
                    let keyword = &other[..space];
                    let rest = other[space..].trim();
                    format!("{} {}", colorize_decision_keyword(keyword), colorize_atom(rest, true))
                } else {
                    colorize_decision_keyword(other)
                }
            }
            other => other.to_string(),
        };
        format!("{}{} {colored_result}", before.dimmed(), "→".dimmed())
    } else {
        s.dimmed().to_string()
    }
}

pub fn colorize_decision_keyword(s: &str) -> String {
    if s == ":allow" {
        s.green().bold().to_string()
    } else if s == ":ask" {
        s.yellow().bold().to_string()
    } else if s == ":deny" {
        s.red().bold().to_string()
    } else {
        s.to_string()
    }
}

/// Colorize an effect s-expression like (effect :ask "reason").
fn colorize_effect_sexpr(s: &str) -> String {
    s.replace(":allow", &":allow".green().bold().to_string())
        .replace(":ask", &":ask".yellow().bold().to_string())
        .replace(":deny", &":deny".red().bold().to_string())
}

// ── Path display ───────────────────────────────────────────────────

/// Replace the home directory prefix with `~` for display.
pub fn shorten_home(path: &std::path::Path) -> String {
    if let Ok(home) = std::env::var("HOME")
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

// ── JSON output ────────────────────────────────────────────────────

/// Serialize trace entries for JSON output.
pub fn trace_to_json(entries: &[TraceEntry]) -> Vec<serde_json::Value> {
    entries.iter().map(|entry| {
        match entry {
            TraceEntry::SegmentHeader { command, decision } => serde_json::json!({
                "type": "segment_header",
                "command": command,
                "decision": decision.to_string(),
            }),
            TraceEntry::DefaultAsk { reason } => serde_json::json!({
                "type": "default_ask",
                "reason": reason,
            }),
            TraceEntry::Rule { doc, line } => {
                let mut annotations = Vec::new();
                collect_json_annotations(doc, &mut annotations);
                serde_json::json!({
                    "type": "rule",
                    "line": line,
                    "structure": doc_to_json(doc),
                    "annotations": annotations,
                })
            }
        }
    }).collect()
}

/// Collect annotations from a Doc tree for JSON serialization.
fn collect_json_annotations(doc: &Doc<Option<EvalAnn>>, out: &mut Vec<serde_json::Value>) {
    if let Some(ann) = &doc.ann {
        out.push(eval_ann_to_json(ann));
    }
    if let DocF::List(children) = &doc.node {
        for child in children {
            collect_json_annotations(child, out);
        }
    }
}

fn eval_ann_to_json(ann: &EvalAnn) -> serde_json::Value {
    match ann {
        EvalAnn::CommandMatch(matched) => serde_json::json!({
            "type": "command_match",
            "matched": matched,
        }),
        EvalAnn::ExprVsArg { arg, matched } => serde_json::json!({
            "type": "expr_vs_arg",
            "arg": arg,
            "matched": matched,
        }),
        EvalAnn::Quantifier { count, matched } => serde_json::json!({
            "type": "quantifier",
            "count": count,
            "matched": matched,
        }),
        EvalAnn::Missing => serde_json::json!({
            "type": "missing",
        }),
        EvalAnn::Anywhere { args, matched } => serde_json::json!({
            "type": "anywhere",
            "args": args,
            "matched": matched,
        }),
        EvalAnn::CondBranch { decision } => serde_json::json!({
            "type": "cond_branch",
            "decision": decision.to_string(),
        }),
        EvalAnn::CondElse { decision } => serde_json::json!({
            "type": "cond_else",
            "decision": decision.to_string(),
        }),
        EvalAnn::ExactRemainder { count } => serde_json::json!({
            "type": "exact_remainder",
            "count": count,
        }),
        EvalAnn::ArgsResult(matched) => serde_json::json!({
            "type": "args_result",
            "matched": matched,
        }),
        EvalAnn::RuleEffect { decision, reason } => serde_json::json!({
            "type": "effect",
            "decision": decision.to_string(),
            "reason": reason,
        }),
        EvalAnn::DefaultAsk => serde_json::json!({
            "type": "default_ask",
        }),
    }
}

/// Serialize a Doc tree to JSON.
fn doc_to_json(doc: &Doc<Option<EvalAnn>>) -> serde_json::Value {
    match &doc.node {
        DocF::Atom(s) => serde_json::json!(s),
        DocF::List(children) => {
            serde_json::json!(children.iter().map(doc_to_json).collect::<Vec<_>>())
        }
    }
}

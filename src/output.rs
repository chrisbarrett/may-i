// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::TraceStep;
use may_i_pp::{Doc, Format, colorize_atom, parse_sexpr, pretty, visible_len};

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

// ── Elision ────────────────────────────────────────────────────────

/// Elide the middle of a row list, keeping the first `keep` and last 1
/// rows, inserting a single `…` | `…` row in the middle.
pub fn elide_rows(mut rows: Vec<Row>, keep: usize) -> Vec<Row> {
    if rows.len() <= keep + 1 {
        return rows;
    }
    let last = rows.pop().unwrap();
    rows.truncate(keep);
    rows.push(Row {
        left: "…".dimmed().to_string(),
        left_visible: 1,
        right: "…".to_string(),
        right_precolored: false,
    });
    rows.push(last);
    rows
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

/// Group flat trace steps into per-rule blocks, then render each as a
/// two-column s-expression: left = rule structure, right = eval result.
pub fn print_trace(steps: &[TraceStep], indent: &str) {
    let layout = detect_layout();
    let blocks = group_into_rule_blocks(steps);

    // Pass 1: build all elements.
    let mut elements: Vec<Element> = Vec::new();
    let mut first = true;

    for block in &blocks {
        if let Some(TraceStep::SegmentHeader { command, decision }) = block.steps.first() {
            if !first {
                elements.push(Element::Blank);
                elements.push(Element::Blank);
            }
            elements.push(segment_header_element(command, *decision));
            let rest = RuleBlock { steps: &block.steps[1..] };
            if !rest.steps.is_empty() {
                elements.push(Element::Table(render_block(&rest, &layout)));
            }
        } else {
            if !first {
                elements.push(Element::Blank);
            }
            elements.push(Element::Table(render_block(block, &layout)));
        }
        first = false;
    }

    // Pass 2: render.
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

/// A block of trace steps belonging to a single rule evaluation (or default).
struct RuleBlock<'a> {
    steps: &'a [TraceStep],
}

/// Split trace steps at Rule boundaries.
fn group_into_rule_blocks(steps: &[TraceStep]) -> Vec<RuleBlock<'_>> {
    let mut blocks = Vec::new();
    let mut start = 0;

    for (i, step) in steps.iter().enumerate() {
        if matches!(step, TraceStep::Rule { .. } | TraceStep::SegmentHeader { .. }) && i > start {
            blocks.push(RuleBlock { steps: &steps[start..i] });
            start = i;
        }
    }
    if start < steps.len() {
        blocks.push(RuleBlock { steps: &steps[start..] });
    }
    blocks
}

/// Render a rule block into rows.
fn render_block(block: &RuleBlock<'_>, layout: &Layout) -> Vec<Row> {
    let mut matching_steps: Vec<&TraceStep> = Vec::new();
    let mut rule_label = String::new();
    let mut rule_line: Option<usize> = None;
    let mut outcome: Option<&TraceStep> = None;
    let mut matched = false;

    for step in block.steps {
        match step {
            TraceStep::Rule { label, line } => {
                rule_label = label.clone();
                rule_line = *line;
            }
            TraceStep::ArgsMatched => { matched = true; }
            TraceStep::ArgsNotMatched => { matched = false; }
            TraceStep::Effect { .. } | TraceStep::DefaultAsk => {
                outcome = Some(step);
            }
            _ => {
                matching_steps.push(step);
            }
        }
    }

    if matching_steps.is_empty() {
        render_simple_rule(&rule_label, rule_line, outcome, layout)
    } else {
        render_rule_with_steps(&rule_label, rule_line, &matching_steps, outcome, matched, layout)
    }
}

/// Render a rule with no matching steps (immediate effect or default).
fn render_simple_rule(
    rule_label: &str,
    rule_line: Option<usize>,
    outcome: Option<&TraceStep>,
    layout: &Layout,
) -> Vec<Row> {
    let mut rows = Vec::new();

    if rule_label.is_empty() {
        if let Some(out) = outcome {
            rows.push(Row::trace("", 0, format_outcome(out)));
        }
        return rows;
    }

    let right = outcome.map(format_outcome).unwrap_or_default();

    let doc = Doc::list(vec![Doc::atom("rule"), parse_sexpr(rule_label)]);
    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    for (i, sline) in rendered_lines.iter().enumerate() {
        let is_last = i == rendered_lines.len() - 1;
        rows.push(Row::trace(
            sline.to_string(),
            visible_len(sline),
            if is_last { right.clone() } else { String::new() },
        ));
    }

    rows
}

/// Render a rule with matching steps as a nested s-expression.
///
/// Builds all rows first, then applies elision to collapse long runs
/// of matching steps (keeping first 2 and last 1).
fn render_rule_with_steps(
    rule_label: &str,
    rule_line: Option<usize>,
    matching_steps: &[&TraceStep],
    outcome: Option<&TraceStep>,
    matched: bool,
    layout: &Layout,
) -> Vec<Row> {
    // Build the full s-expression Doc and annotations without truncation.
    let annotations: Vec<String> = matching_steps.iter()
        .map(|s| format_matching_step_right(s))
        .collect();

    let mut children = vec![Doc::atom("rule"), parse_sexpr(rule_label)];
    for step in matching_steps {
        children.push(step_to_doc(step));
    }
    let doc = Doc::list(children);

    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    // Build rows: pair each rendered line with its annotation.
    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let num_steps = annotations.len();
    let total_lines = rendered_lines.len();
    let step_start = total_lines.saturating_sub(num_steps);

    let mut header_rows = Vec::new();
    let mut step_rows = Vec::new();

    for (i, sline) in rendered_lines.iter().enumerate() {
        let right = if i >= step_start {
            annotations[i - step_start].clone()
        } else {
            String::new()
        };
        let row = Row::trace(sline.to_string(), visible_len(sline), right);
        if i < step_start {
            header_rows.push(row);
        } else {
            step_rows.push(row);
        }
    }

    // Elide long step runs: keep first 2, last 1.
    let step_rows = elide_rows(step_rows, 2);

    let mut rows = header_rows;
    rows.extend(step_rows);

    if let Some(out) = outcome
        && matched
    {
        rows.push(Row::trace("", 0, format_outcome(out)));
    }

    rows
}

/// Convert a matching step into a Doc for embedding in the rule s-expression.
fn step_to_doc(step: &TraceStep) -> Doc {
    match step {
        TraceStep::ExprVsArg { expr, .. } => parse_sexpr(expr),
        TraceStep::Quantifier { label, .. } => parse_sexpr(label),
        TraceStep::Missing { label } => parse_sexpr(label),
        TraceStep::Anywhere { label, .. } => parse_sexpr(label),
        TraceStep::ExprCondBranch { label, .. } => parse_sexpr(label),
        TraceStep::MatcherCondElse { .. } => Doc::atom("else"),
        TraceStep::ExactRemainder { count } => Doc::atom(format!("{count} extra args")),
        _ => Doc::atom(""),
    }
}

/// Format the right-column annotation for a matching step.
fn format_matching_step_right(step: &TraceStep) -> String {
    match step {
        TraceStep::ExprVsArg { expr, arg, matched } => {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            if expr.starts_with("(regex ") {
                format!("{arg} ~ {expr} {arrow}")
            } else {
                format!("{arg} = {expr} {arrow}")
            }
        }
        TraceStep::Quantifier { count, matched, .. } => {
            if *matched {
                format!("{count} matched → yes")
            } else {
                "→ no".into()
            }
        }
        TraceStep::Missing { .. } => "→ missing".into(),
        TraceStep::Anywhere { label, args, matched } => {
            let pattern = extract_anywhere_pattern(label);
            let truncated = truncate_list(args, 4);
            let arrow = if *matched { "→ yes" } else { "→ no" };
            format!("{pattern} ∈ {{{truncated}}} {arrow}")
        }
        TraceStep::ExprCondBranch { decision, .. } => format!("→ :{decision}"),
        TraceStep::MatcherCondBranch { decision } => format!("→ :{decision}"),
        TraceStep::MatcherCondElse { decision } => format!("→ :{decision}"),
        TraceStep::ExactRemainder { count } => format!("{count} extra args"),
        _ => String::new(),
    }
}

/// Extract the pattern from an anywhere label like `(anywhere "--hard")`.
fn extract_anywhere_pattern(label: &str) -> &str {
    label
        .strip_prefix("(anywhere ")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(label)
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

/// Format an outcome step for the right column.
fn format_outcome(step: &TraceStep) -> String {
    match step {
        TraceStep::Effect { decision, reason } => {
            match reason {
                Some(r) => format!("→ :{decision} \"{r}\""),
                None => format!("→ :{decision}"),
            }
        }
        TraceStep::DefaultAsk => "→ :ask (default)".into(),
        _ => String::new(),
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

/// Serialize trace steps for JSON output.
pub fn trace_to_json(steps: &[TraceStep]) -> Vec<serde_json::Value> {
    steps.iter().map(|step| {
        match step {
            TraceStep::Rule { label, line } => serde_json::json!({
                "type": "rule",
                "label": label,
                "line": line,
            }),
            TraceStep::ExprVsArg { expr, arg, matched } => serde_json::json!({
                "type": "expr_vs_arg",
                "expr": expr,
                "arg": arg,
                "matched": matched,
            }),
            TraceStep::Quantifier { label, count, matched } => serde_json::json!({
                "type": "quantifier",
                "label": label,
                "count": count,
                "matched": matched,
            }),
            TraceStep::Missing { label } => serde_json::json!({
                "type": "missing",
                "label": label,
            }),
            TraceStep::ExprCondBranch { label, decision } => serde_json::json!({
                "type": "expr_cond_branch",
                "label": label,
                "decision": decision.to_string(),
            }),
            TraceStep::MatcherCondBranch { decision } => serde_json::json!({
                "type": "matcher_cond_branch",
                "decision": decision.to_string(),
            }),
            TraceStep::MatcherCondElse { decision } => serde_json::json!({
                "type": "matcher_cond_else",
                "decision": decision.to_string(),
            }),
            TraceStep::Anywhere { label, args, matched } => serde_json::json!({
                "type": "anywhere",
                "label": label,
                "args": args,
                "matched": matched,
            }),
            TraceStep::ExactRemainder { count } => serde_json::json!({
                "type": "exact_remainder",
                "count": count,
            }),
            TraceStep::ArgsMatched => serde_json::json!({ "type": "args_matched" }),
            TraceStep::ArgsNotMatched => serde_json::json!({ "type": "args_not_matched" }),
            TraceStep::Effect { decision, reason } => serde_json::json!({
                "type": "effect",
                "decision": decision.to_string(),
                "reason": reason,
            }),
            TraceStep::DefaultAsk => serde_json::json!({ "type": "default_ask" }),
            TraceStep::SegmentHeader { command, decision } => serde_json::json!({
                "type": "segment_header",
                "command": command,
                "decision": decision.to_string(),
            }),
        }
    }).collect()
}

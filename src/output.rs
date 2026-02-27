// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::TraceStep;
use may_i_pp::{Doc, Format, parse_sexpr, pretty, truncate_long_lists, visible_len};

// ── Layout geometry ────────────────────────────────────────────────

/// Minimum usable terminal width before we stop trying to fit two columns.
const MIN_TERM_WIDTH: usize = 40;

/// The indent prefix printed before each trace line.
const INDENT: &str = "  ";

/// Unicode box-drawing character used as a column divider.
const DIVIDER: &str = "│";

/// Layout parameters derived from the terminal width.
struct Layout {
    /// Maximum visible width for the left (s-expression) column.
    left_width: usize,
    /// Total usable width after indent.
    usable: usize,
}

fn detect_layout() -> Layout {
    let term_width = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80);
    let usable = term_width.saturating_sub(INDENT.len()).max(MIN_TERM_WIDTH);
    let left_width = usable / 2;
    Layout { left_width, usable }
}

/// Compute the divider column: min(half the terminal, widest left content + gap).
fn divider_column(lines: &[PrintableLine], layout: &Layout) -> usize {
    let max_left = lines.iter()
        .map(|l| match l {
            PrintableLine::Trace(tl) => tl.left_visible,
            _ => 0,
        })
        .max()
        .unwrap_or(0);
    (max_left + 2).min(layout.left_width + 1)
}

// ── Two-column s-expression trace ──────────────────────────────────

/// A line in the two-column trace layout.
struct TraceLine {
    /// Left column (colorized s-expression fragment). Contains ANSI codes.
    left: String,
    /// Visible width of the left column (excluding ANSI).
    left_visible: usize,
    /// Right column annotation (plain text, colorized at print time).
    right: String,
}

/// An element in the flat printable output.
enum PrintableLine {
    Blank,
    SegmentHeader { command: String, decision: may_i_core::Decision },
    Trace(TraceLine),
}

/// Group flat trace steps into per-rule blocks, then render each as a
/// two-column s-expression: left = rule structure, right = eval result.
pub fn print_trace(steps: &[TraceStep], indent: &str) {
    let layout = detect_layout();
    let blocks = group_into_rule_blocks(steps);

    // Pass 1: render all blocks into a flat list.
    let mut output: Vec<PrintableLine> = Vec::new();
    let mut first = true;

    for block in &blocks {
        if let Some(TraceStep::SegmentHeader { command, decision }) = block.steps.first() {
            if !first {
                output.push(PrintableLine::Blank);
            }
            output.push(PrintableLine::SegmentHeader {
                command: command.clone(),
                decision: *decision,
            });
            let rest = RuleBlock { steps: &block.steps[1..] };
            if !rest.steps.is_empty() {
                for line in render_block(&rest, &layout) {
                    output.push(PrintableLine::Trace(line));
                }
            }
        } else {
            if !first {
                output.push(PrintableLine::Blank);
            }
            for line in render_block(block, &layout) {
                output.push(PrintableLine::Trace(line));
            }
        }
        first = false;
    }

    // Pass 2: compute divider column from actual content.
    let divider_col = divider_column(&output, &layout);

    // Pass 3: print.
    for line in &output {
        match line {
            PrintableLine::Blank => println!(),
            PrintableLine::SegmentHeader { command, decision } => {
                print_segment_header(indent, command, *decision, layout.usable);
            }
            PrintableLine::Trace(tl) => {
                print_two_col(indent, tl, divider_col);
            }
        }
    }
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

/// Render a rule block into two-column lines using the pp crate for
/// s-expression fontification and layout.
fn render_block(block: &RuleBlock<'_>, layout: &Layout) -> Vec<TraceLine> {
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
) -> Vec<TraceLine> {
    let mut lines = Vec::new();

    if rule_label.is_empty() {
        if let Some(out) = outcome {
            lines.push(TraceLine {
                left: String::new(),
                left_visible: 0,
                right: format_outcome(out),
            });
        }
        return lines;
    }

    let right = outcome.map(format_outcome).unwrap_or_default();

    let doc = truncate_long_lists(
        &Doc::list(vec![Doc::atom("rule"), parse_sexpr(rule_label)]),
        3,
    );
    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    for (i, sline) in rendered_lines.iter().enumerate() {
        let is_last = i == rendered_lines.len() - 1;
        lines.push(TraceLine {
            left_visible: visible_len(sline),
            left: sline.to_string(),
            right: if is_last { right.clone() } else { String::new() },
        });
    }

    lines
}

/// Render a rule with matching steps as a nested s-expression.
fn render_rule_with_steps(
    rule_label: &str,
    rule_line: Option<usize>,
    matching_steps: &[&TraceStep],
    outcome: Option<&TraceStep>,
    matched: bool,
    layout: &Layout,
) -> Vec<TraceLine> {
    let mut lines = Vec::new();

    let annotations: Vec<String> = matching_steps.iter()
        .map(|s| format_matching_step_right(s))
        .collect();

    let mut children = vec![Doc::atom("rule"), parse_sexpr(rule_label)];
    for step in matching_steps {
        children.push(step_to_doc(step));
    }
    let doc = truncate_long_lists(&Doc::list(children), 3);

    let fmt = Format {
        width: layout.left_width,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let num_steps = matching_steps.len();
    let total_lines = rendered_lines.len();
    let step_start = total_lines.saturating_sub(num_steps);

    for (i, sline) in rendered_lines.iter().enumerate() {
        let right = if i >= step_start {
            let step_idx = i - step_start;
            annotations.get(step_idx).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        lines.push(TraceLine {
            left_visible: visible_len(sline),
            left: sline.to_string(),
            right,
        });
    }

    if let Some(out) = outcome
        && matched
    {
        lines.push(TraceLine {
            left: String::new(),
            left_visible: 0,
            right: format_outcome(out),
        });
    }

    lines
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
///
/// Conventions:
///   a = b   → yes/no   (literal comparison)
///   a ~ b   → yes/no   (regex match)
///   in [..] → yes/no   (anywhere search)
fn format_matching_step_right(step: &TraceStep) -> String {
    match step {
        TraceStep::ExprVsArg { expr, arg, matched } => {
            let arrow = if *matched { "→ yes" } else { "→ no" };
            if expr.starts_with("(regex ") {
                format!("{arg} ~ {expr} {arrow}")
            } else if let Some(elts) = extract_set_elements(expr) {
                format!("{arg} ∈ {{{elts}}} {arrow}")
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

/// Extract inner elements from `(or ...)` or `(and ...)` as a comma-separated string.
fn extract_set_elements(expr: &str) -> Option<String> {
    let inner = if let Some(rest) = expr.strip_prefix("(or ") {
        rest.strip_suffix(')')
    } else if let Some(rest) = expr.strip_prefix("(and ") {
        rest.strip_suffix(')')
    } else {
        None
    }?;
    let elts: Vec<&str> = inner.split_whitespace().collect();
    Some(elts.join(", "))
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

// ── Two-column printing ────────────────────────────────────────────

/// Print a single two-column line with a box-drawing divider.
fn print_two_col(indent: &str, line: &TraceLine, divider_col: usize) {
    if line.left.is_empty() && line.right.is_empty() {
        return;
    }

    let left_pad = divider_col.saturating_sub(line.left_visible);

    if line.right.is_empty() {
        println!(
            "{indent}{}{:pad$}{}",
            line.left,
            "",
            DIVIDER.dimmed(),
            pad = left_pad,
        );
    } else {
        let colored_right = colorize_right(&line.right);
        println!(
            "{indent}{}{:pad$}{} {}",
            line.left,
            "",
            DIVIDER.dimmed(),
            colored_right,
            pad = left_pad,
        );
    }
}

/// Print a segment header: `─── command ───────────────────────────`.
fn print_segment_header(indent: &str, command: &str, decision: may_i_core::Decision, usable: usize) {
    use may_i_core::Decision;
    let colored_cmd = match decision {
        Decision::Allow => command.green().bold().to_string(),
        Decision::Ask => command.yellow().bold().to_string(),
        Decision::Deny => command.red().bold().to_string(),
    };
    let prefix = "─── ";
    let mid = " ";
    let used = prefix.len() + command.len() + mid.len();
    let remaining = usable.saturating_sub(used);
    let suffix = "─".repeat(remaining);
    println!(
        "{indent}{}{}{}{}",
        prefix.dimmed(),
        colored_cmd,
        mid.dimmed(),
        suffix.dimmed(),
    );
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
            other if other.starts_with(':') => colorize_keyword(other),
            other => other.to_string(),
        };
        format!("{}{} {colored_result}", before.dimmed(), "→".dimmed())
    } else {
        s.dimmed().to_string()
    }
}

fn colorize_keyword(s: &str) -> String {
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

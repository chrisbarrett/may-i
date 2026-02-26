// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::TraceStep;
use may_i_pp::{Doc, Format, parse_sexpr, pretty, truncate_long_lists, visible_len};

// ── Two-column s-expression trace ──────────────────────────────────

/// Maximum width for the left (s-expression) column before wrapping.
const MAX_LEFT_COL: usize = 60;

/// A line in the two-column trace layout.
struct TraceLine {
    /// Left column (colorized s-expression fragment). Contains ANSI codes.
    left: String,
    /// Visible width of the left column (excluding ANSI).
    left_width: usize,
    /// Right column annotation (plain text, colorized at print time).
    right: String,
}

/// Group flat trace steps into per-rule blocks, then render each as a
/// two-column s-expression: left = rule structure, right = eval result.
pub fn print_trace(steps: &[TraceStep], indent: &str) {
    let blocks = group_into_rule_blocks(steps);
    let mut first = true;

    for block in &blocks {
        // Check if this block starts with a SegmentHeader.
        if let Some(TraceStep::SegmentHeader { command, decision }) = block.steps.first() {
            println!();
            print_segment_header(indent, command, *decision);
            // Render the rest of the block (after the header).
            let rest = RuleBlock { steps: &block.steps[1..] };
            if !rest.steps.is_empty() {
                println!();
                let lines = render_block(&rest);
                let right_col = compute_right_column(&lines);
                for line in &lines {
                    print_two_col(indent, line, right_col);
                }
            }
        } else {
            if !first {
                println!();
            }
            let lines = render_block(block);
            let right_col = compute_right_column(&lines);
            for line in &lines {
                print_two_col(indent, line, right_col);
            }
        }
        first = false;
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
fn render_block(block: &RuleBlock<'_>) -> Vec<TraceLine> {
    let mut matching_steps: Vec<&TraceStep> = Vec::new();
    let mut rule_label = String::new();
    let mut rule_line: Option<usize> = None;
    let mut outcome: Option<&TraceStep> = None;
    let mut matched = false;

    // Classify steps within this block.
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
        render_simple_rule(&rule_label, rule_line, outcome)
    } else {
        render_rule_with_steps(&rule_label, rule_line, &matching_steps, outcome, matched)
    }
}

/// Render a rule with no matching steps (immediate effect or default).
fn render_simple_rule(
    rule_label: &str,
    rule_line: Option<usize>,
    outcome: Option<&TraceStep>,
) -> Vec<TraceLine> {
    let mut lines = Vec::new();

    if rule_label.is_empty() {
        // DefaultAsk with no rule.
        if let Some(out) = outcome {
            lines.push(TraceLine {
                left: String::new(),
                left_width: 0,
                right: format_outcome(out),
            });
        }
        return lines;
    }

    let right = outcome.map(format_outcome).unwrap_or_default();

    // Build Doc: (rule <command-label>)
    let doc = truncate_long_lists(
        &Doc::list(vec![Doc::atom("rule"), parse_sexpr(rule_label)]),
        3,
    );
    let fmt = Format {
        width: MAX_LEFT_COL,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    for (i, sline) in rendered_lines.iter().enumerate() {
        let is_last = i == rendered_lines.len() - 1;
        lines.push(TraceLine {
            left_width: visible_len(sline),
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
) -> Vec<TraceLine> {
    let mut lines = Vec::new();

    // Collect right-column annotations for each matching step.
    let annotations: Vec<String> = matching_steps.iter()
        .map(|s| format_matching_step_right(s))
        .collect();

    // Build Doc: (rule <command-label> <step1> <step2> ...)
    let mut children = vec![Doc::atom("rule"), parse_sexpr(rule_label)];
    for step in matching_steps {
        children.push(step_to_doc(step));
    }
    let doc = truncate_long_lists(&Doc::list(children), 3);

    let fmt = Format {
        width: MAX_LEFT_COL,
        color: true,
        line_number: rule_line,
    };
    let rendered = pretty(&doc, 0, &fmt);

    let rendered_lines: Vec<&str> = rendered.lines().collect();
    let num_steps = matching_steps.len();
    let total_lines = rendered_lines.len();
    // In pp's broken layout, the last N lines correspond to the N matching steps.
    // The header (rule + command) occupies the lines before those.
    let step_start = total_lines.saturating_sub(num_steps);

    for (i, sline) in rendered_lines.iter().enumerate() {
        let right = if i >= step_start {
            let step_idx = i - step_start;
            annotations.get(step_idx).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        lines.push(TraceLine {
            left_width: visible_len(sline),
            left: sline.to_string(),
            right,
        });
    }

    // Outcome annotation on a new line after the s-expression.
    if let Some(out) = outcome
        && matched
    {
        lines.push(TraceLine {
            left: String::new(),
            left_width: 0,
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
fn format_matching_step_right(step: &TraceStep) -> String {
    match step {
        TraceStep::ExprVsArg { arg, matched, .. } => {
            let result = if *matched { "yes" } else { "no" };
            format!("{arg} {result}")
        }
        TraceStep::Quantifier { count, matched, .. } => {
            if *matched {
                format!("yes ({count})")
            } else {
                "no".into()
            }
        }
        TraceStep::Missing { .. } => "<missing>".into(),
        TraceStep::Anywhere { matched, .. } => {
            if *matched { "yes" } else { "no" }.into()
        }
        TraceStep::ExprCondBranch { decision, .. } => format!("(effect :{decision})"),
        TraceStep::MatcherCondBranch { decision } => format!("(effect :{decision})"),
        TraceStep::MatcherCondElse { decision } => format!("(effect :{decision})"),
        TraceStep::ExactRemainder { .. } => String::new(),
        _ => String::new(),
    }
}

/// Format an outcome step for the right column.
fn format_outcome(step: &TraceStep) -> String {
    match step {
        TraceStep::Effect { decision, reason } => {
            match reason {
                Some(r) => format!("(effect :{decision} \"{r}\")"),
                None => format!("(effect :{decision})"),
            }
        }
        TraceStep::DefaultAsk => "(default :ask)".into(),
        _ => String::new(),
    }
}

/// Find the column where right-side annotations should start.
fn compute_right_column(lines: &[TraceLine]) -> usize {
    let max_left = lines.iter()
        .filter(|l| !l.right.is_empty())
        .map(|l| l.left_width)
        .max()
        .unwrap_or(0);
    // Minimum gap of 4 spaces, and at least column 40.
    (max_left + 4).max(40)
}

/// Print a single two-column line with colorization.
fn print_two_col(indent: &str, line: &TraceLine, right_col: usize) {
    if line.left.is_empty() && line.right.is_empty() {
        return;
    }

    if line.right.is_empty() {
        println!("{indent}{}", line.left);
    } else {
        let padding = right_col.saturating_sub(line.left_width);
        let colored_right = colorize_right(&line.right);
        println!("{indent}{}{:pad$}{colored_right}", line.left, "", pad = padding);
    }
}

/// Print a segment header: `─── command ───────────────────────────`.
fn print_segment_header(indent: &str, command: &str, decision: may_i_core::Decision) {
    use may_i_core::Decision;
    let colored_cmd = match decision {
        Decision::Allow => command.green().bold().to_string(),
        Decision::Ask => command.yellow().bold().to_string(),
        Decision::Deny => command.red().bold().to_string(),
    };
    let visible_cmd_len = command.len();
    let prefix = "─── ";
    let mid = " ";
    let used = prefix.len() + visible_cmd_len + mid.len();
    let remaining = 72usize.saturating_sub(used);
    let suffix = "─".repeat(remaining);
    println!(
        "{indent}{}{}{}{}",
        prefix.dimmed(),
        colored_cmd,
        mid.dimmed(),
        suffix.dimmed(),
    );
}

/// Colorize the right column (evaluation results).
fn colorize_right(s: &str) -> String {
    if s == "yes" || s.starts_with("yes ") {
        let rest = &s[3..];
        format!("{}{}", "yes".green().bold(), rest.dimmed())
    } else if s == "no" {
        "no".yellow().to_string()
    } else if s == "<missing>" {
        "<missing>".yellow().to_string()
    } else if s.starts_with("(effect ") || s.starts_with("(default ") {
        colorize_effect_sexpr(s)
    } else if s.ends_with(" yes") || s.ends_with(" no") {
        // "arg" yes/no — color the arg dimmed, result colored.
        if let Some(pos) = s.rfind(' ') {
            let (arg, result) = s.split_at(pos);
            let result = result.trim();
            let colored_result = if result == "yes" {
                "yes".green().bold().to_string()
            } else {
                "no".yellow().to_string()
            };
            format!("{} {colored_result}", arg.dimmed())
        } else {
            s.to_string()
        }
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
            TraceStep::Anywhere { label, matched } => serde_json::json!({
                "type": "anywhere",
                "label": label,
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

// Shared display helpers for trace output.

use colored::Colorize;
use may_i_core::TraceStep;

/// Render a TraceStep to a human-readable string (for printing).
fn format_step(step: &TraceStep) -> String {
    match step {
        TraceStep::Rule { label, line } => {
            match line {
                Some(n) => format!("{n}: rule {label}"),
                None => format!("rule {label}"),
            }
        }
        TraceStep::ExprVsArg { expr, arg, matched } => {
            let result = if *matched { "yes" } else { "no" };
            format!("  {expr} vs {arg} => {result}")
        }
        TraceStep::Quantifier { label, count, matched } => {
            let result = if *matched {
                format!("yes (matched {count})")
            } else {
                "no".into()
            };
            format!("  {label} => {result}")
        }
        TraceStep::Missing { label } => {
            format!("  {label} vs <missing> => no")
        }
        TraceStep::ExprCondBranch { label, decision } => {
            format!("  {label} => yes [{decision}]")
        }
        TraceStep::MatcherCondBranch { decision } => {
            format!("  => yes [{decision}]")
        }
        TraceStep::MatcherCondElse { decision } => {
            format!("  else => [{decision}]")
        }
        TraceStep::Anywhere { label, matched } => {
            let result = if *matched { "yes" } else { "no" };
            format!("  {label} => {result}")
        }
        TraceStep::ExactRemainder { count } => {
            format!("  exact: {count} positional args remaining")
        }
        TraceStep::ArgsMatched => "  args matched".into(),
        TraceStep::ArgsNotMatched => "  args did not match".into(),
        TraceStep::Effect { decision, reason } => {
            format!(
                "  effect: {} — {}",
                decision,
                reason.as_deref().unwrap_or("(no reason)")
            )
        }
        TraceStep::DefaultAsk => "  => ask (default)".into(),
    }
}

/// Print trace steps with colorization.
pub fn print_trace(steps: &[TraceStep], indent: &str) {
    let lines: Vec<String> = steps.iter().map(format_step).collect();

    // Compute arrow alignment: find max position of " => " for arg-match steps.
    let arrow_positions: Vec<usize> = lines.iter()
        .filter_map(|l| l.rfind(" => "))
        .collect();
    let arrow_col = if arrow_positions.is_empty() {
        0
    } else {
        let mut sorted = arrow_positions.clone();
        sorted.sort();
        sorted[sorted.len() / 4] // First quartile to avoid outliers.
    };

    let mut first_rule = true;
    for (step, line) in steps.iter().zip(&lines) {
        if matches!(step, TraceStep::Rule { .. }) {
            if !first_rule {
                println!();
            }
            first_rule = false;
            println!("{indent}{}", line.bold());
            let rule_width = line.len().max(40);
            println!("{indent}{}", "─".repeat(rule_width).dimmed());
        } else {
            println!("{indent}{}", colorize_trace_line(line, arrow_col));
        }
    }
}

/// Colorize a trace line: dim `=>` arrows, green `yes`, yellow `no`, italic `vs`.
fn colorize_trace_line(line: &str, arrow_col: usize) -> String {
    // Italicize " vs " separators.
    let line = line.replace(" vs ", &format!(" {} ", "vs".italic()));
    if let Some(pos) = line.rfind(" => ") {
        let (before, rest) = line.split_at(pos);
        let after = &rest[4..]; // skip " => "
        let padding = arrow_col.saturating_sub(before.len());
        let arrow = " => ".dimmed();
        let colored_after = if let Some(rest) = after.strip_prefix("yes") {
            format!("{}{rest}", "yes".green().bold())
        } else if let Some(rest) = after.strip_prefix("no") {
            format!("{}{rest}", "no".yellow())
        } else {
            after.to_string()
        };
        format!("{before}{:>pad$}{arrow}{colored_after}", "", pad = padding)
    } else {
        line.to_string()
    }
}

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
        }
    }).collect()
}

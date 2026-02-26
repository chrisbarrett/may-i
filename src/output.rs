// Shared display helpers for trace output.

use colored::Colorize;

/// Print trace steps with aligned `=>` columns and horizontal rules under headings.
pub fn print_trace(steps: &[String], indent: &str) {
    use std::collections::HashMap;

    // Compute arrow alignment per indentation depth, using median to avoid outliers.
    let mut positions_by_depth: HashMap<usize, Vec<usize>> = HashMap::new();
    for step in steps {
        let depth = step.len() - step.trim_start().len();
        if let Some(pos) = step.rfind(" => ") {
            positions_by_depth.entry(depth).or_default().push(pos);
        }
    }
    let arrow_by_depth: HashMap<usize, usize> = positions_by_depth.into_iter().map(|(depth, mut positions)| {
        positions.sort();
        // Use first quartile to avoid long lines dominating alignment.
        let idx = (positions.len().saturating_sub(1)) / 4;
        (depth, positions[idx])
    }).collect();

    // Track heading state: (start_depth, arrow_col, paren_balance).
    let mut heading: Option<(usize, usize, i32)> = None;
    let mut first_rule = true;

    for step in steps {
        let trimmed = step.trim_start();
        let depth = step.len() - trimmed.len();
        let arrow_col = arrow_by_depth.get(&depth).copied().unwrap_or(0);

        // Detect heading starts. Rule lines may have a "N: " line number prefix.
        let is_rule_heading = trimmed.starts_with("rule ")
            || trimmed.split_once(": ").is_some_and(|(n, rest)| {
                n.chars().all(|c| c.is_ascii_digit()) && rest.starts_with("rule ")
            });
        let is_heading_start = is_rule_heading || trimmed == "cond"
            || trimmed.starts_with("cond vs ");

        if is_heading_start && heading.is_none() {
            if is_rule_heading && !first_rule {
                println!();
            }
            if is_rule_heading {
                first_rule = false;
            }
            heading = Some((depth, arrow_col, 0));
        }

        // Track paren balance for multi-line headings.
        if let Some((_, _, ref mut balance)) = heading {
            for ch in step.chars() {
                if ch == '(' { *balance += 1; }
                if ch == ')' { *balance -= 1; }
            }
        }

        // Multi-line steps: print each line.
        for sub_line in step.split('\n') {
            println!("{indent}{}", colorize_trace_step(sub_line, arrow_col));
        }

        // Place horizontal rule after the heading is complete (parens balanced or no parens).
        if let Some((rule_depth, rule_arrow, balance)) = heading
            && balance <= 0
        {
            let rule_width = (rule_arrow + 20).max(rule_depth + 40) - rule_depth;
            let step_indent_str = " ".repeat(rule_depth);
            println!("{indent}{step_indent_str}{}", "─".repeat(rule_width).dimmed());
            heading = None;
        }
    }
}

/// Colorize a trace step: dim `=>` arrows, green `yes`, yellow `no`, italic `vs`.
/// Pads the left side of `=>` to align at `arrow_col`.
fn colorize_trace_step(step: &str, arrow_col: usize) -> String {
    // Italicize " vs " separators
    let step = step.replace(" vs ", &format!(" {} ", "vs".italic()));
    if let Some(pos) = step.rfind(" => ") {
        let (before, rest) = step.split_at(pos);
        let after = &rest[4..]; // skip " => "
        // Pad before to align the arrow at arrow_col
        let visible_len = may_i_pp::visible_len(before);
        let padding = arrow_col.saturating_sub(visible_len);
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
        step.to_string()
    }
}

// Intent: render `cmd_check` failure reports and summary.
//
// `cmd_check` constructs a `CheckFailureView` per failed check and hands it
// off; layout assembly (label hrule, kv rows, trace block) lives here so the
// command body does not touch `Layout` primitives.

use std::io::Write;

use colored::Colorize;
use may_i_core::{ContextFacts, Decision};
use may_i_output::{ColRow, HRuleLabel, Layout};
use may_i_pp::colorize_atom;

use super::{Terminal, colorize_decision_keyword, shorten_home, write_layout, write_trace};
use crate::annotation::TraceEntry;

/// All data a `cmd_check` failure needs to be rendered. Lifetimes borrow from
/// `CheckResult` and its tracing extras — no copies.
pub struct CheckFailureView<'a> {
    pub command: &'a str,
    pub expected: Decision,
    pub actual: Decision,
    pub context: &'a ContextFacts,
    pub location: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub traces: &'a [TraceEntry],
}

/// Render the verbose per-result PASS/FAIL line for `cmd_check`. `passed`
/// drives both the label colour and which of expected/actual is shown.
pub fn render_check_verbose_line(
    w: &mut impl Write,
    command: &str,
    expected: Decision,
    actual: Decision,
    passed: bool,
) {
    if passed {
        let _ = writeln!(
            w,
            "  {} {}",
            "PASS".green().bold(),
            format!("{command} → {actual}").dimmed()
        );
    } else {
        let _ = writeln!(
            w,
            "  {} {}",
            "FAIL".red().bold(),
            format!("{command} → {actual} (expected {expected})").yellow()
        );
    }
}

/// Render one failed check to `w`. Includes the labelled separator, the
/// source location, the expected/actual/context/reason rows, and the trace
/// block (when present).
pub fn render_check_failure(w: &mut impl Write, term: &Terminal, failure: &CheckFailureView<'_>) {
    let icon = "✗".red().bold().to_string();
    let label = format!("{icon} {}", failure.command.bold());
    let label_width = 2 + failure.command.len();
    render_labelled_separator(w, term, "", Some((&label, label_width)));
    let _ = writeln!(w);

    let loc = failure.location.unwrap_or("<unknown>");
    let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
    let short_file = shorten_home(std::path::Path::new(file));
    let _ = write!(w, "{}", short_file.dimmed());
    if !line_col.is_empty() {
        let _ = write!(w, "{}", format!(":{line_col}").dimmed());
    }
    let _ = writeln!(w);

    let expected_kw = format!(":{}", failure.expected);
    let actual_kw = format!(":{}", failure.actual);
    let mut rows = vec![
        ColRow::kv("expected", colorize_decision_keyword(&expected_kw)),
        ColRow::kv("actual", colorize_decision_keyword(&actual_kw)),
    ];
    if failure.context.iter().next().is_some() {
        rows.push(ColRow::kv("context", render_context(failure.context)));
    }
    if let Some(reason) = failure.reason {
        let quoted = format!("\"{reason}\"");
        rows.push(ColRow::kv("reason", colorize_atom(&quoted, true)));
    }
    let layout = Layout::Indent(2, Box::new(Layout::Columns(rows)));
    write_layout(w, &layout, term);

    if !failure.traces.is_empty() {
        let _ = writeln!(w, "\n  {}\n", "Trace".bold());
        write_trace(w, failure.traces, failure.command, "  ", term);
    }
}

/// Render the `cmd_check` summary block to `w` with the pass/fail counts and
/// the config path. The caller is responsible for the trailing rule.
pub fn render_check_summary(
    w: &mut impl Write,
    _term: &Terminal,
    passed: usize,
    failed: usize,
    display_path: &str,
) {
    let _ = writeln!(w, "\n{}\n", "Summary".bold());
    let icon = if failed > 0 {
        "✗".red()
    } else {
        "✓".green()
    };
    let _ = writeln!(
        w,
        "  {icon} {} passed, {} failed",
        passed.to_string().bold(),
        failed.to_string().bold()
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "  {} {}", "config:".dimmed(), display_path.dimmed());
}

/// Render an HRule (optionally labelled) at `indent`. Used between failures
/// and to close the failure section before the summary.
pub fn render_labelled_separator(
    w: &mut impl Write,
    term: &Terminal,
    indent: &str,
    label: Option<(&str, usize)>,
) {
    let hrule_label = label.map(|(text, w)| HRuleLabel {
        text: text.to_string(),
        visible_width: w,
    });
    let layout = Layout::HRule(hrule_label);
    let indented = Layout::Indent(indent.len(), Box::new(layout));
    write_layout(w, &indented, term);
}

fn render_context(context: &ContextFacts) -> String {
    context
        .iter()
        .map(|(key, values)| {
            if values.is_empty() {
                key.to_string()
            } else {
                let vals: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
                format!("{key}={}", vals.join(","))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::strip_ansi;

    #[test]
    fn render_check_verbose_line_pass_shows_actual_only() {
        let mut buf = Vec::new();
        render_check_verbose_line(
            &mut buf,
            "git status",
            Decision::Allow,
            Decision::Allow,
            true,
        );
        let out = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(out.contains("PASS"));
        assert!(out.contains("git status"));
        assert!(out.contains("allow"));
        assert!(!out.contains("expected"));
    }

    #[test]
    fn render_check_verbose_line_fail_shows_expected_and_actual() {
        let mut buf = Vec::new();
        render_check_verbose_line(&mut buf, "rm -rf /", Decision::Deny, Decision::Allow, false);
        let out = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(out.contains("FAIL"));
        assert!(out.contains("rm -rf /"));
        assert!(out.contains("allow"));
        assert!(out.contains("expected deny"));
    }
}

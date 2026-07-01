// Intent: render `cmd_check` output as a single per-subcommand builder.
//
// `cmd_check` constructs a `CheckOutput` carrying per-result views and
// hands it to `.render(w, pipeline)`. The builder owns the full sequence:
// prelude advisories → trust warning → verbose lines → failure details →
// separator → summary. Leaf renderers below are crate-private and
// reachable only through this builder.

use std::io::Write;
use std::path::Path;

use may_i_core::{ContextFacts, Decision};
use may_i_output::{Advisory, ColRow, HRuleLabel, Layout, NoteLevel, Style, Styled, write_line};

use super::{Terminal, colorize_decision_keyword, shorten_home, write_layout, write_trace};
use crate::annotation::TraceEntry;

/// All data a single `cmd_check` result needs to be rendered, either as a
/// verbose PASS/FAIL line or as a full failure block. Lifetimes borrow from
/// the underlying `CheckResult` and its tracing extras — no copies.
pub struct CheckResultView<'a> {
    pub command: &'a str,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub context: &'a ContextFacts,
    pub location: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub traces: &'a [TraceEntry],
}

/// Per-subcommand text-output builder for `may-i check`. Owns the full
/// rendering script (prelude → trust warning → body); the caller hands it
/// per-result views plus the resolved config path.
pub struct CheckOutput<'a> {
    pub config_path: &'a Path,
    pub results: &'a [CheckResultView<'a>],
    pub verbose: bool,
    /// Names of scope-dependent env rules with no `(with-env …)` coverage,
    /// rendered as a leading `warn` advisory.
    pub untested_scope_rules: &'a [String],
}

impl CheckOutput<'_> {
    /// Emit the `may-i check` text body (advisory, verbose lines, failure
    /// detail blocks, separator, summary) to `w`.
    pub fn render(&self, w: &mut impl Write, term: &Terminal) {
        self.render_untested_scope_advisory(w, term);
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = self.results.len() - passed;

        let mut failures: Vec<&CheckResultView<'_>> = Vec::new();
        for r in self.results {
            if self.verbose {
                render_check_verbose_line(w, term, r.command, r.expected, r.actual, r.passed);
            }
            if !r.passed {
                failures.push(r);
            }
        }

        for (i, r) in failures.iter().enumerate() {
            if i > 0 {
                let _ = writeln!(w);
            }
            let _ = writeln!(w);
            render_check_failure(w, term, r);
        }

        if !failures.is_empty() {
            let _ = writeln!(w);
            render_labelled_separator(w, term, "", None);
        }
        let display_path = shorten_home(self.config_path);
        render_check_summary(w, term, passed, failed, &display_path);
    }

    /// Render the non-failing `warn` advisory for scope-dependent env rules
    /// that no `(with-env …)` case exercises. No-op when there are none.
    fn render_untested_scope_advisory(&self, w: &mut impl Write, term: &Terminal) {
        if self.untested_scope_rules.is_empty() {
            return;
        }
        let listing = Layout::Stack(
            self.untested_scope_rules
                .iter()
                .map(|name| Layout::Text(Styled::atom(name)))
                .collect::<Vec<_>>(),
        );
        let layout = Advisory {
            level: NoteLevel::Warn,
            heading: "Untested scope-dependent env rule(s)".into(),
            detail: "These (env …) rules branch on (scope …), but no (check …) \
                     case declares the name in a (with-env …). The hermetic \
                     default entry environment is empty, so the reaching-write \
                     branch — covering always-exported names like PATH and LD_* \
                     — is never exercised."
                .into(),
            suggestion: "Add a check declaring the name, e.g.:".into(),
            command: "(with-env [\"PATH\"] (ask \"PATH=/evil:$PATH\"))".into(),
            children: vec![listing],
        }
        .into_layout();
        write_layout(w, &layout, term);
        let _ = writeln!(w);
    }
}

/// Render the verbose per-result PASS/FAIL line for `cmd_check`. `passed`
/// drives both the label colour and which of expected/actual is shown.
pub(crate) fn render_check_verbose_line(
    w: &mut impl Write,
    term: &Terminal,
    command: &str,
    expected: Decision,
    actual: Decision,
    passed: bool,
) {
    let line = if passed {
        Styled::plain("  ")
            .with("PASS", Style::Allow)
            .with(" ", Style::Plain)
            .with(format!("{command} → {actual}"), Style::Dimmed)
    } else {
        Styled::plain("  ")
            .with("FAIL", Style::Deny)
            .with(" ", Style::Plain)
            .with(
                format!("{command} → {actual} (expected {expected})"),
                Style::AskSoft,
            )
    };
    write_line(w, &line, term);
}

/// Render one failed check to `w`. Includes the labelled separator, the
/// source location, the expected/actual/context/reason rows, and the trace
/// block (when present).
pub(crate) fn render_check_failure(
    w: &mut impl Write,
    term: &Terminal,
    failure: &CheckResultView<'_>,
) {
    let label = Styled::span("✗", Style::Deny)
        .with(" ", Style::Plain)
        .with(failure.command, Style::Strong);
    render_labelled_separator(w, term, "", Some(label));
    let _ = writeln!(w);

    let loc = failure.location.unwrap_or("<unknown>");
    let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
    let short_file = shorten_home(std::path::Path::new(file));
    let mut loc_line = Styled::span(short_file, Style::Dimmed);
    if !line_col.is_empty() {
        loc_line.push(format!(":{line_col}"), Style::Dimmed);
    }
    write_line(w, &loc_line, term);

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
        rows.push(ColRow::kv("reason", Styled::atom(&quoted)));
    }
    let layout = Layout::Indent(2, Box::new(Layout::Columns(rows)));
    write_layout(w, &layout, term);

    if !failure.traces.is_empty() {
        let _ = writeln!(w);
        write_line(w, &Styled::plain("  ").with("Trace", Style::Strong), term);
        let _ = writeln!(w);
        write_trace(w, failure.traces, failure.command, "  ", term);
    }
}

/// Render the `cmd_check` summary block to `w` with the pass/fail counts and
/// the config path. The caller is responsible for the trailing rule.
pub(crate) fn render_check_summary(
    w: &mut impl Write,
    term: &Terminal,
    passed: usize,
    failed: usize,
    display_path: &str,
) {
    let _ = writeln!(w);
    write_line(w, &Styled::span("Summary", Style::Strong), term);
    let _ = writeln!(w);
    let (icon, icon_style) = if failed > 0 {
        ("✗", Style::DenySoft)
    } else {
        ("✓", Style::AllowSoft)
    };
    let summary = Styled::plain("  ")
        .with(icon, icon_style)
        .with(" ", Style::Plain)
        .with(passed.to_string(), Style::Strong)
        .with(" passed, ", Style::Plain)
        .with(failed.to_string(), Style::Strong)
        .with(" failed", Style::Plain);
    write_line(w, &summary, term);
    let _ = writeln!(w);
    write_line(
        w,
        &Styled::plain("  ")
            .with("config:", Style::Dimmed)
            .with(" ", Style::Plain)
            .with(display_path, Style::Dimmed),
        term,
    );
}

/// Render an HRule (optionally labelled) at `indent`. Used between failures
/// and to close the failure section before the summary.
pub(crate) fn render_labelled_separator(
    w: &mut impl Write,
    term: &Terminal,
    indent: &str,
    label: Option<Styled>,
) {
    let hrule_label = label.map(HRuleLabel::from);
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
    use std::path::PathBuf;

    use may_i_core::ContextFacts;

    use super::*;

    const TERM: Terminal = Terminal {
        width: 80,
        color: false,
    };

    #[test]
    fn render_check_verbose_line_pass_shows_actual_only() {
        let mut buf = Vec::new();
        render_check_verbose_line(
            &mut buf,
            &TERM,
            "git status",
            Decision::Allow,
            Decision::Allow,
            true,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("PASS"));
        assert!(out.contains("git status"));
        assert!(out.contains("allow"));
        assert!(!out.contains("expected"));
    }

    #[test]
    fn render_check_verbose_line_fail_shows_expected_and_actual() {
        let mut buf = Vec::new();
        render_check_verbose_line(
            &mut buf,
            &TERM,
            "rm -rf /",
            Decision::Deny,
            Decision::Allow,
            false,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("FAIL"));
        assert!(out.contains("rm -rf /"));
        assert!(out.contains("allow"));
        assert!(out.contains("expected deny"));
    }

    fn render_check_output(views: &[CheckResultView<'_>], verbose: bool) -> String {
        temp_env::with_var("COLUMNS", Some("80"), || {
            let config_path = PathBuf::from("/tmp/test-config.lisp");
            let builder = CheckOutput {
                config_path: &config_path,
                results: views,
                verbose,
                untested_scope_rules: &[],
            };
            let term = Terminal::detect();
            let mut buf = Vec::new();
            builder.render(&mut buf, &term);
            String::from_utf8(buf).unwrap()
        })
    }

    #[test]
    fn check_output_all_passed_summary_only() {
        let context = ContextFacts::default();
        let views = vec![CheckResultView {
            command: "echo hi",
            expected: Decision::Allow,
            actual: Decision::Allow,
            passed: true,
            context: &context,
            location: None,
            reason: None,
            traces: &[],
        }];
        insta::assert_snapshot!(render_check_output(&views, false));
    }

    #[test]
    fn check_output_with_failure_shows_detail_block() {
        let context = ContextFacts::default();
        let views = vec![CheckResultView {
            command: "rm -rf /",
            expected: Decision::Deny,
            actual: Decision::Allow,
            passed: false,
            context: &context,
            location: Some("/tmp/test-config.lisp:3:4"),
            reason: Some("rule matched"),
            traces: &[],
        }];
        insta::assert_snapshot!(render_check_output(&views, false));
    }

    #[test]
    fn check_output_verbose_lists_every_result() {
        let context = ContextFacts::default();
        let views = vec![
            CheckResultView {
                command: "echo hi",
                expected: Decision::Allow,
                actual: Decision::Allow,
                passed: true,
                context: &context,
                location: None,
                reason: None,
                traces: &[],
            },
            CheckResultView {
                command: "rm -rf /",
                expected: Decision::Deny,
                actual: Decision::Deny,
                passed: true,
                context: &context,
                location: None,
                reason: None,
                traces: &[],
            },
        ];
        insta::assert_snapshot!(render_check_output(&views, true));
    }
}

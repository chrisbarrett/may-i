// Check subcommand — validate config and run checks.

use colored::Colorize;
use may_i_core::{ContextFacts, ContextValue, TraceEntry};
use may_i_pp::colorize_atom;

use may_i_config as config;
use may_i_engine as engine;

use crate::output;
use crate::output::trace_to_json;

// =============================================================================
// CheckReport Builder
// =============================================================================

/// Display representation of a single check result.
#[derive(Debug, Clone)]
struct CheckResultDisplay {
    command: String,
    expected: String,
    actual: String,
    passed: bool,
    facts: ContextFacts,
    reason: Option<String>,
    trace: Vec<TraceEntry>,
    location: Option<String>,
}

/// Summary statistics for check results.
#[derive(Debug, Clone)]
struct CheckSummary {
    passed: usize,
    failed: usize,
}

/// A warning to display.
#[derive(Debug, Clone)]
struct CheckWarning {
    message: String,
    location: String,
    help: Option<String>,
}

/// Builder for check command output.
/// Separates data extraction from rendering.
#[derive(Debug, Clone)]
struct CheckReport {
    warnings: Vec<CheckWarning>,
    results: Vec<CheckResultDisplay>,
    summary: CheckSummary,
    config_path: std::path::PathBuf,
}

impl CheckReport {
    /// Extract data from engine results and config into a structured report.
    fn from_engine_results(
        results: &[engine::CheckResult],
        config: &may_i_core::Config,
        config_path: &std::path::Path,
    ) -> Self {
        let warnings: Vec<CheckWarning> = config
            .warnings
            .iter()
            .map(|w| CheckWarning {
                message: w.message.clone(),
                location: config
                    .source_info
                    .as_ref()
                    .map(|si| si.location_of(w.span))
                    .unwrap_or_else(|| "<unknown>".to_string()),
                help: w.help.clone(),
            })
            .collect();

        let results: Vec<CheckResultDisplay> = results
            .iter()
            .map(|r| CheckResultDisplay {
                command: r.command.clone(),
                expected: r.expected.to_string(),
                actual: r.actual.to_string(),
                passed: r.passed,
                facts: r.context.clone(),
                reason: r.reason.clone(),
                trace: r.trace.clone(),
                location: r.location.clone(),
            })
            .collect();

        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.len() - passed;

        Self {
            warnings,
            results,
            summary: CheckSummary { passed, failed },
            config_path: config_path.to_path_buf(),
        }
    }

    /// Returns true if any checks failed.
    fn has_failures(&self) -> bool {
        self.summary.failed > 0
    }

    /// Get the exit code (0 for success, 1 for failure).
    fn exit_code(&self) -> i32 {
        if self.has_failures() { 1 } else { 0 }
    }

    /// Render the report as human-readable text.
    fn render_text(&self, verbose: bool) -> String {
        let mut output = String::new();

        // Render warnings
        if !self.warnings.is_empty() {
            output.push_str(&format!("\n{}\n\n", "Warnings".yellow().bold()));
            for warning in &self.warnings {
                output.push_str(&format!(
                    "  {} {}\n",
                    "WARN".yellow().bold(),
                    warning.message.yellow()
                ));
                output.push_str(&format!("       {}\n", warning.location.dimmed()));
                if let Some(help) = &warning.help {
                    output.push_str(&format!("       {} {}\n", "help:".dimmed(), help.dimmed()));
                }
            }
        }

        // Collect failures for detailed output
        let failures: Vec<_> = self.results.iter().filter(|r| !r.passed).collect();

        // Render verbose output (all results)
        if verbose {
            for r in &self.results {
                if r.passed {
                    output.push_str(&format!(
                        "  {} {}\n",
                        "PASS".green().bold(),
                        format!("{} → {}", r.command, r.actual).dimmed()
                    ));
                } else {
                    output.push_str(&format!(
                        "  {} {}\n",
                        "FAIL".red().bold(),
                        format!("{} → {} (expected {})", r.command, r.actual, r.expected).red()
                    ));
                }
            }
        }

        // Render failure details
        for (i, r) in failures.iter().enumerate() {
            if i > 0 || verbose {
                output.push('\n');
            }

            output.push('\n');
            let icon = "✗".red().bold().to_string();
            let label = format!("{icon} {}", r.command.bold());
            let label_width = 2 + r.command.len();
            output.push_str(&output::render_separator_str(
                "",
                Some((&label, label_width)),
            ));
            output.push('\n');

            // Location
            let loc = r.location.as_deref().unwrap_or("<unknown>");
            let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
            let short_file = output::shorten_home(std::path::Path::new(file));
            output.push_str(&short_file.dimmed().to_string());
            if !line_col.is_empty() {
                output.push_str(&format!("{}", format!(":{line_col}").dimmed()));
            }
            output.push('\n');

            let expected_kw = format!(":{}", r.expected);
            let actual_kw = format!(":{}", r.actual);
            let mut rows = vec![
                output::Row::kv("expected", output::colorize_decision_keyword(&expected_kw)),
                output::Row::kv("actual", output::colorize_decision_keyword(&actual_kw)),
            ];
            if r.facts.iter().next().is_some() {
                rows.push(output::Row::kv("context", render_context(&r.facts)));
            }
            if let Some(reason) = &r.reason {
                let quoted = format!("\"{reason}\"");
                rows.push(output::Row::kv("reason", colorize_atom(&quoted, true)));
            }
            output.push_str(&output::render_elements_str(
                "  ",
                &[output::Element::Table(rows)],
            ));

            // Trace
            if !r.trace.is_empty() {
                output.push_str(&format!("\n  {}\n\n", "Trace".bold()));
                output.push_str(&output::format_trace(&r.trace, "  "));
            }
        }

        if !failures.is_empty() {
            output.push('\n');
            output.push_str(&output::render_separator_str("", None));
        }

        // Render summary
        output.push_str(&format!("\n{}\n\n", "Summary".bold()));
        let icon = if self.summary.failed > 0 {
            "✗".red()
        } else {
            "✓".green()
        };
        output.push_str(&format!(
            "  {icon} {} passed, {} failed\n",
            self.summary.passed.to_string().bold(),
            self.summary.failed.to_string().bold()
        ));
        output.push('\n');
        let display_path = output::shorten_home(&self.config_path);
        output.push_str(&format!(
            "  {} {}\n",
            "config:".dimmed(),
            display_path.dimmed()
        ));

        output
    }

    /// Render the report as JSON.
    fn to_json(&self) -> serde_json::Value {
        let json_results: Vec<serde_json::Value> = self
            .results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "command": r.command,
                    "expected": r.expected,
                    "actual": r.actual,
                    "passed": r.passed,
                    "facts": context_to_json(&r.facts),
                    "location": r.location,
                    "reason": r.reason,
                    "trace": trace_to_json(&r.trace),
                })
            })
            .collect();

        let json_warnings: Vec<serde_json::Value> = self
            .warnings
            .iter()
            .map(|w| {
                serde_json::json!({
                    "message": w.message,
                    "location": w.location,
                    "help": w.help,
                })
            })
            .collect();

        serde_json::json!({
            "passed": self.summary.passed,
            "failed": self.summary.failed,
            "warnings": json_warnings,
            "results": json_results
        })
    }
}

pub fn cmd_check(
    json_mode: bool,
    verbose: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let config = config::load(&config_file)?;
    let results = engine::run_checks(&config);

    // Build the report
    let report = CheckReport::from_engine_results(&results, &config, &config_file);

    if json_mode {
        let output = report.to_json();
        println!(
            "{}",
            serde_json::to_string(&output).expect("response serialization is infallible")
        );
    } else {
        let output = report.render_text(verbose);
        print!("{}", output);
    }

    // Exit with appropriate code
    std::process::exit(report.exit_code());
}

fn context_to_json(context: &ContextFacts) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, value) in context.iter() {
        let value = match value {
            ContextValue::Present => serde_json::Value::Bool(true),
            ContextValue::Scalar(value) => serde_json::Value::String(value.clone()),
        };
        obj.insert(key.to_string(), value);
    }
    serde_json::Value::Object(obj)
}

fn render_context(context: &ContextFacts) -> String {
    context
        .iter()
        .map(|(key, value)| match value {
            ContextValue::Present => key.to_string(),
            ContextValue::Scalar(value) => format!("{key}={value}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::{Decision, TraceEntry};

    fn create_test_check_report(all_passed: bool) -> CheckReport {
        let mut facts = ContextFacts::default();
        facts.insert_scalar("user", "test");
        facts.insert_present("interactive");

        let results = vec![
            CheckResultDisplay {
                command: "ls".to_string(),
                expected: "allow".to_string(),
                actual: "allow".to_string(),
                passed: true,
                facts: facts.clone(),
                reason: None,
                trace: vec![TraceEntry::SegmentHeader {
                    command: "ls".to_string(),
                    decision: Decision::Allow,
                }],
                location: Some("/test/config.yaml:10".to_string()),
            },
            CheckResultDisplay {
                command: "rm -rf /".to_string(),
                expected: if all_passed {
                    "deny".to_string()
                } else {
                    "allow".to_string()
                },
                actual: "deny".to_string(),
                passed: all_passed,
                facts: facts.clone(),
                reason: Some("Dangerous command".to_string()),
                trace: vec![TraceEntry::SegmentHeader {
                    command: "rm -rf /".to_string(),
                    decision: Decision::Deny,
                }],
                location: Some("/test/config.yaml:20".to_string()),
            },
        ];

        CheckReport {
            warnings: vec![CheckWarning {
                message: "Test warning".to_string(),
                location: "/test/config.yaml:5".to_string(),
                help: Some("This is a test".to_string()),
            }],
            results,
            summary: CheckSummary {
                passed: if all_passed { 2 } else { 1 },
                failed: if all_passed { 0 } else { 1 },
            },
            config_path: std::path::PathBuf::from("/test/config.yaml"),
        }
    }

    #[test]
    fn test_check_report_render_text_with_failures() {
        let report = create_test_check_report(false);
        let output = report.render_text(false);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_check_report_render_text_verbose() {
        let report = create_test_check_report(false);
        let output = report.render_text(true);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_check_report_render_text_all_passed() {
        let report = create_test_check_report(true);
        let output = report.render_text(false);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_check_report_to_json() {
        let report = create_test_check_report(false);
        let json = report.to_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        insta::assert_snapshot!(json_str);
    }

    #[test]
    fn test_check_report_to_json_all_passed() {
        let report = create_test_check_report(true);
        let json = report.to_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        insta::assert_snapshot!(json_str);
    }
}

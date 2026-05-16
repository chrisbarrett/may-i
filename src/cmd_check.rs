// Check subcommand — validate config and run checks with trace output.

use colored::Colorize;

use engine::check::CheckResult;
use may_i_engine as engine;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output::{self, CheckFailureView};
use crate::pipeline::CommandPipeline;

/// Error indicating one or more checks failed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0} check(s) failed")]
pub struct CheckFailure(pub usize);

struct TraceExtra {
    location: Option<String>,
    traces: Vec<TraceEntry>,
}

pub fn cmd_check(pipeline: &mut CommandPipeline, verbose: bool) -> miette::Result<()> {
    pipeline.render_prelude_advisories();
    // `cmd_check` validates the config as authored, so it does NOT filter
    // untrusted Loaded rules; it just renders the warning advisory.
    pipeline.render_trust_warning();

    let results = run_checks_with_traces(pipeline.loaded())?;

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;

    let config_file = pipeline.config_path().to_path_buf();

    if pipeline.json() {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "command": r.command,
                    "expected": r.expected.to_string(),
                    "actual": r.actual.to_string(),
                    "passed": r.passed,
                    "context": context_to_json(&r.context),
                    "location": r.extra.location,
                    "reason": r.reason,
                    "trace": output::trace_to_json(&r.extra.traces),
                })
            })
            .collect();

        let body = serde_json::json!({
            "passed": passed,
            "failed": failed,
            "results": json_results
        });
        println!(
            "{}",
            serde_json::to_string(&body).expect("response serialization is infallible")
        );
    } else {
        let term = pipeline.terminal();
        let mut failures = Vec::new();

        for r in &results {
            if verbose {
                if r.passed {
                    println!(
                        "  {} {}",
                        "PASS".green().bold(),
                        format!("{} → {}", r.command, r.actual).dimmed()
                    );
                } else {
                    println!(
                        "  {} {}",
                        "FAIL".red().bold(),
                        format!("{} → {} (expected {})", r.command, r.actual, r.expected).yellow()
                    );
                }
            }
            if !r.passed {
                failures.push(r);
            }
        }

        let mut stdout = std::io::stdout();
        for (i, r) in failures.iter().enumerate() {
            if i > 0 {
                println!();
            }
            println!();
            let view = CheckFailureView {
                command: &r.command,
                expected: r.expected,
                actual: r.actual,
                context: &r.context,
                location: r.extra.location.as_deref(),
                reason: r.reason.as_deref(),
                traces: &r.extra.traces,
            };
            output::render_check_failure(&mut stdout, term, &view);
        }

        if !failures.is_empty() {
            println!();
            output::render_labelled_separator(&mut stdout, term, "", None);
        }
        let display_path = output::shorten_home(&config_file);
        output::render_check_summary(&mut stdout, term, passed, failed, &display_path);
    }

    if failed > 0 {
        return Err(CheckFailure(failed).into());
    }

    Ok(())
}

/// Run all checks using TracingFold to capture traces for failure reporting.
fn run_checks_with_traces(
    loaded: &may_i_config::LoadResult,
) -> miette::Result<Vec<CheckResult<TraceExtra>>> {
    use may_i_core::span::offset_to_line_col;

    let file_str = loaded.config_path.display().to_string();

    let make_location = |span: &may_i_core::Span| -> Option<String> {
        loaded.source_text.as_ref().map(|source| {
            let (line, col) = offset_to_line_col(source, span.start);
            format!("{file_str}:{line}:{col}")
        })
    };

    engine::check::run_checks_with(&loaded.config, |check| {
        let mut fold = TracingFold::from_load_result(loaded);
        let result = engine::eval::evaluate_command_with_fold(
            &check.command,
            &loaded.config,
            &check.context,
            &mut fold,
        )
        .map_err(|e| miette::miette!("{e}"))?;
        Ok((
            result,
            TraceExtra {
                location: make_location(&check.span),
                traces: fold.traces,
            },
        ))
    })
}

fn context_to_json(context: &may_i_core::ContextFacts) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, values) in context.iter() {
        if values.is_empty() {
            obj.insert(key.to_string(), serde_json::Value::Bool(true));
        } else if values.len() == 1 {
            obj.insert(
                key.to_string(),
                serde_json::Value::String(values.iter().next().unwrap().clone()),
            );
        } else {
            let arr: Vec<serde_json::Value> = values
                .iter()
                .map(|v| serde_json::Value::String(v.clone()))
                .collect();
            obj.insert(key.to_string(), serde_json::Value::Array(arr));
        }
    }
    serde_json::Value::Object(obj)
}

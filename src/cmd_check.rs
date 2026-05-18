// Check subcommand — validate config and run checks with trace output.

use engine::check::CheckResult;
use may_i_engine as engine;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output::{self, CheckOutput, CheckResultView};
use crate::pipeline::CommandPipeline;

/// Error indicating one or more checks failed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0} check(s) failed")]
pub struct CheckFailure(pub usize);

pub struct TraceExtra {
    pub location: Option<String>,
    pub traces: Vec<TraceEntry>,
}

pub fn cmd_check(pipeline: &mut CommandPipeline, verbose: bool) -> miette::Result<()> {
    let results = run_checks_with_traces(pipeline.loaded())?;

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;

    if pipeline.json() {
        let body = output::render_check_results_json(passed, failed, &results);
        println!(
            "{}",
            serde_json::to_string(&body).expect("response serialization is infallible")
        );
    } else {
        let config_path = pipeline.config_path().to_path_buf();
        let views: Vec<CheckResultView<'_>> = results
            .iter()
            .map(|r| CheckResultView {
                command: &r.command,
                expected: r.expected,
                actual: r.actual,
                passed: r.passed,
                context: &r.context,
                location: r.extra.location.as_deref(),
                reason: r.reason.as_deref(),
                traces: &r.extra.traces,
            })
            .collect();
        let builder = CheckOutput {
            config_path: &config_path,
            results: &views,
            verbose,
        };
        builder.render(&mut std::io::stdout(), pipeline);
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

// Check subcommand — validate config and run checks with trace output.

use std::cell::Cell;

use engine::check::CheckResult;
use may_i_engine as engine;

use crate::annotation::{TraceEntry, TracingFold};
use crate::pipeline::{CheckOutcomeBody, CommandPipeline};

/// Error indicating one or more checks failed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0} check(s) failed")]
pub struct CheckFailure(pub usize);

pub struct TraceExtra {
    pub location: Option<String>,
    pub traces: Vec<TraceEntry>,
}

/// The exit-1 signal lives outside `run_check`: a failed-check count drives
/// the process exit code (a clap-driver concern), and `run_check` itself
/// returns `Ok(())` after rendering. We capture the count from inside the
/// closure via this `Cell` so the post-`run_check` check can promote it to
/// `CheckFailure`.
pub fn cmd_check(pipeline: &mut CommandPipeline, verbose: bool) -> miette::Result<()> {
    let failed_signal = Cell::new(0usize);

    pipeline.run_check(|ctx| {
        let results = run_checks_with_traces(ctx.loaded)?;
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.len() - passed;
        failed_signal.set(failed);
        Ok(CheckOutcomeBody {
            results,
            verbose,
            passed,
            failed,
            display_path: ctx.display_path.clone(),
        })
    })?;

    let failed = failed_signal.get();
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

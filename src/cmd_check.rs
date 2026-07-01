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
        // A scope-dependent env rule whose name no check declares in
        // `(with-env …)` is never exercised under the hermetic empty default.
        // Advise (warn) — it does not fail the run.
        let untested_scope_rules = engine::check::untested_scope_env_rules(&ctx.loaded.config);
        Ok(CheckOutcomeBody {
            results,
            verbose,
            passed,
            failed,
            display_path: ctx.display_path.clone(),
            untested_scope_rules,
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
        // `check` is hermetic: the entry environment comes only from the case's
        // `(with-env …)` declaration (defaulting to empty), never the host.
        let result = engine::eval::evaluate_command_with_fold_env(
            &check.command,
            &loaded.config,
            &check.context,
            &check.entry_env,
            // `check` is dialect-hermetic — always Bash, independent of the
            // ambient `$SHELL`.
            may_i_shell_parser::Dialect::Bash,
            &mut fold,
        )
        .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))?;
        Ok((
            result,
            TraceExtra {
                location: make_location(&check.span),
                traces: fold.traces,
            },
        ))
    })
}

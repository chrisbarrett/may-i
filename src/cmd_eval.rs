// Eval subcommand — evaluate a command and print result with trace.

use std::io::Write;

use colored::Colorize;

use may_i_core::Decision;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::pipeline::{CommandPipeline, EvalOutcomeBody};
use crate::runtime_facts::parse_cli_facts;

pub fn cmd_eval(
    pipeline: &mut CommandPipeline,
    command: &str,
    raw_facts: &[String],
) -> miette::Result<()> {
    let context_facts = parse_cli_facts(raw_facts)?;

    pipeline.run_eval(command, |ctx| {
        let (result, mut traces, colored_command) =
            evaluate_with_colorization(command, ctx.loaded, &context_facts)?;
        if !result.parse_diagnostics.is_empty() {
            traces.push(TraceEntry::ParseDiagnostics {
                diagnostics: result.parse_diagnostics.clone(),
            });
        }
        for diag in &result.parse_diagnostics {
            let err = crate::shell_parse_error::ShellParseError::from_diagnostic(diag, command);
            let _ = writeln!(std::io::stderr(), "{:?}", miette::Report::new(err));
        }
        Ok(EvalOutcomeBody {
            command: command.to_string(),
            colored: colored_command,
            result,
            traces,
            display_path: ctx.display_path.clone(),
        })
    })
}

/// Evaluate a command using the unified pipeline, then colorize using segments
/// for display purposes only.
pub fn evaluate_with_colorization(
    command: &str,
    loaded: &may_i_config::LoadResult,
    context: &may_i_core::ContextFacts,
) -> miette::Result<(engine::EvalResult, Vec<TraceEntry>, String)> {
    let mut fold = TracingFold::from_load_result(loaded);
    let result =
        engine::eval::evaluate_command_with_fold(command, &loaded.config, context, &mut fold)
            .map_err(|e| miette::miette!("{e}"))?;

    let segments = parser::segment(command);
    let colored_command = if segments.is_empty() {
        colorize_text(command, result.decision)
    } else {
        colorize_segments(command, &segments, &result.segment_decisions)
    };

    Ok((result, fold.traces, colored_command))
}

fn colorize_text(text: &str, decision: Decision) -> String {
    match decision {
        Decision::Allow => text.green().underline().to_string(),
        Decision::Ask => text.yellow().underline().to_string(),
        Decision::Deny => text.red().underline().to_string(),
    }
}

/// Colorize each top-level command segment using the engine's
/// `segment_decisions`. The strictest decision among all engine units that
/// overlap a parser segment determines the colour, so an `echo $(rm)`
/// segment colours red even though the `echo` part on its own would allow.
fn colorize_segments(
    command: &str,
    segments: &[parser::Segment],
    segment_decisions: &[engine::SegmentDecision],
) -> String {
    let mut display_parts = Vec::new();
    for seg in segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            let decision = strictest_overlapping(seg.start, seg.end, segment_decisions)
                .unwrap_or(Decision::Ask);
            display_parts.push(colorize_text(text, decision));
        }
    }
    display_parts.concat()
}

fn strictest_overlapping(
    start: usize,
    end: usize,
    decisions: &[engine::SegmentDecision],
) -> Option<Decision> {
    decisions
        .iter()
        .filter(|d| d.start < end && d.end > start)
        .map(|d| d.decision)
        .max()
}

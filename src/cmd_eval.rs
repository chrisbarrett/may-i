// Eval subcommand — evaluate a command and print result with trace.

use std::io::Write;

use colored::Colorize;

use may_i_core::Decision;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;
use crate::pipeline::CommandPipeline;
use crate::runtime_facts::parse_cli_facts;
use crate::trust::TrustMode;

pub fn cmd_eval(
    pipeline: &mut CommandPipeline,
    command: &str,
    raw_facts: &[String],
) -> miette::Result<()> {
    let context = parse_cli_facts(raw_facts)?;
    pipeline.render_prelude_advisories();

    let mode = TrustMode::for_eval(pipeline.json());
    if let Err(block) = pipeline.consult_trust(command, mode) {
        if pipeline.json() {
            let body = serde_json::json!({
                "decision": block.decision.to_string(),
                "reason": block.reason,
                "files": block.files,
            });
            println!(
                "{}",
                serde_json::to_string(&body).expect("response serialization is infallible")
            );
        }
        return Ok(());
    }

    if pipeline.json() {
        let mut fold = TracingFold::from_load_result(pipeline.loaded());
        let result = engine::eval::evaluate_command_with_fold(
            command,
            pipeline.config(),
            &context,
            &mut fold,
        )
        .map_err(|e| miette::miette!("{e}"))?;
        if !result.parse_diagnostics.is_empty() {
            fold.traces.push(TraceEntry::ParseDiagnostics {
                diagnostics: result.parse_diagnostics.clone(),
            });
        }
        let mut json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "trace": output::trace_to_json(&fold.traces),
        });
        if !result.parse_diagnostics.is_empty() {
            json["parse_diagnostics"] = serde_json::json!(
                result
                    .parse_diagnostics
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "span": { "start": d.span.start, "end": d.span.end },
                            "kind": d.kind,
                            "severity": d.severity,
                            "message": d.message(),
                        })
                    })
                    .collect::<Vec<_>>()
            );
        }
        println!(
            "{}",
            serde_json::to_string(&json).expect("response serialization is infallible")
        );
    } else {
        let (result, mut traces, colored_command) =
            evaluate_with_colorization(command, pipeline.loaded(), &context)?;
        if !result.parse_diagnostics.is_empty() {
            traces.push(TraceEntry::ParseDiagnostics {
                diagnostics: result.parse_diagnostics.clone(),
            });
        }
        for diag in &result.parse_diagnostics {
            let err = crate::shell_parse_error::ShellParseError::from_diagnostic(diag, command);
            let _ = writeln!(std::io::stderr(), "{:?}", miette::Report::new(err));
        }
        let display_path = output::shorten_home(pipeline.config_path());
        output::render_eval_result(
            &mut std::io::stdout(),
            pipeline.terminal(),
            command,
            &colored_command,
            &traces,
            &result,
            &display_path,
        );
    }

    Ok(())
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

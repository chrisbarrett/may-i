// Eval subcommand — evaluate a command and print result with trace.

use may_i_core::Decision;
use may_i_engine as engine;
use may_i_output::{Style, Styled};
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::audit::AuditTap;
use crate::pipeline::{CommandPipeline, EvalOutcomeBody};
use crate::runtime_facts::parse_cli_facts;

pub fn cmd_eval(
    pipeline: &mut CommandPipeline,
    command: &str,
    raw_facts: &[String],
) -> miette::Result<()> {
    let context_facts = parse_cli_facts(raw_facts)?;

    pipeline.run_eval(command, |ctx| {
        let (result, mut traces, colored_command, audit_rules) =
            evaluate_with_colorization(command, ctx.loaded, &context_facts)?;
        if !result.parse_diagnostics.is_empty() {
            traces.push(TraceEntry::ParseDiagnostics {
                diagnostics: result.parse_diagnostics.clone(),
            });
        }
        for diag in &result.parse_diagnostics {
            let err = crate::shell_parse_error::ShellParseError::from_diagnostic(diag, command);
            crate::sink::report(&miette::Report::new(err));
        }
        let audit = AuditTap::from_eval(&result, command, audit_rules, None);
        Ok(EvalOutcomeBody {
            command: command.to_string(),
            colored: colored_command,
            result,
            traces,
            display_path: ctx.display_path.clone(),
            audit,
        })
    })
}

/// Evaluate a command using the unified pipeline, then colorize using segments
/// for display purposes only. Returns the engine result, the captured trace,
/// the colourised echo, and the canonical-form hashes of the deciding rules
/// (for the Audit log).
pub fn evaluate_with_colorization(
    command: &str,
    loaded: &may_i_config::LoadResult,
    context: &may_i_core::ContextFacts,
) -> miette::Result<(engine::EvalResult, Vec<TraceEntry>, Styled, Vec<String>)> {
    // Eval needs both the Trace it renders and the audit capture: compose the
    // two folds over one traversal. Projection runs through the TracingFold
    // half, so the returned decision is unchanged.
    let mut fold = engine::ComposedFold::new(
        TracingFold::from_load_result(loaded),
        engine::AuditFold::new(),
    );
    let result =
        engine::eval::evaluate_command_with_fold(command, &loaded.config, context, &mut fold)
            .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))?;

    let segments = parser::segment(command);
    let colored_command = if segments.is_empty() {
        Styled::span(command, echo_style(result.decision))
    } else {
        colorize_segments(command, &segments, &result.segment_decisions)
    };

    let (tracing, audit) = fold.into_parts();
    let audit_rules = audit.into_deciding_hashes(result.decision);
    Ok((result, tracing.traces, colored_command, audit_rules))
}

fn echo_style(decision: Decision) -> Style {
    match decision {
        Decision::Allow => Style::EchoAllow,
        Decision::Ask => Style::EchoAsk,
        Decision::Deny => Style::EchoDeny,
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
) -> Styled {
    let mut out = Styled::new();
    for seg in segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            out.push(format!(" {text} "), Style::Plain);
        } else {
            let decision = strictest_overlapping(seg.start, seg.end, segment_decisions)
                .unwrap_or(Decision::Ask);
            out.push(text, echo_style(decision));
        }
    }
    out
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

// Eval subcommand — evaluate a command and print result with trace.

use std::io::Write;

use colored::Colorize;

use may_i_core::Decision;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;
use crate::runtime_facts::parse_cli_facts;
use crate::trust_gate::{self, GateMode, GateOutcome};

pub fn cmd_eval(
    command: &str,
    raw_facts: &[String],
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let mut loaded = may_i_config::load_and_resolve(config_path)?;
    let config_file = &loaded.config_path.clone();
    let context = parse_cli_facts(raw_facts)?;

    if json_mode {
        let config = std::mem::take(&mut loaded.config);
        match trust_gate::evaluate(config, command, GateMode::Json) {
            GateOutcome::Block { reason, files, .. } => {
                let block = serde_json::json!({
                    "decision": "ask",
                    "reason": reason,
                    "files": files,
                });
                println!(
                    "{}",
                    serde_json::to_string(&block).expect("response serialization is infallible")
                );
                return Ok(());
            }
            GateOutcome::Proceed { config, .. } => {
                loaded.config = config;
            }
        }

        let mut fold = TracingFold::from_load_result(&loaded);
        let result =
            engine::eval::evaluate_command_with_fold(command, &loaded.config, &context, &mut fold)
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
        let term = output::Terminal::detect();
        if let Some(note) = crate::notes::migration_note(&loaded, config_file) {
            output::write_layout(&mut std::io::stderr(), &note, &term);
        }
        // Integrity advisories are orthogonal to the gate; render before it.
        crate::trust_advisory::write_integrity_advisories(&loaded.config, &term);

        let config = std::mem::take(&mut loaded.config);
        match trust_gate::evaluate(config, command, GateMode::Text) {
            GateOutcome::Proceed { config, advisory } => {
                loaded.config = config;
                if let Some(layout) = advisory {
                    output::write_layout(&mut std::io::stderr(), &layout, &term);
                }
            }
            GateOutcome::Block { .. } => unreachable!("text mode never blocks"),
        }

        let (result, mut traces, colored_command) =
            evaluate_with_colorization(command, &loaded, &context)?;
        if !result.parse_diagnostics.is_empty() {
            traces.push(TraceEntry::ParseDiagnostics {
                diagnostics: result.parse_diagnostics.clone(),
            });
        }
        // Render miette diagnostics on stderr
        for diag in &result.parse_diagnostics {
            let err = crate::shell_parse_error::ShellParseError::from_diagnostic(diag, command);
            let _ = writeln!(std::io::stderr(), "{:?}", miette::Report::new(err));
        }
        let display_path = output::shorten_home(config_file);
        write_eval_output(
            &mut std::io::stdout(),
            &traces,
            command,
            &colored_command,
            &result,
            &display_path,
            &term,
        );
    }

    Ok(())
}

/// Render trace + result output to a writer.
pub fn write_eval_output(
    w: &mut impl Write,
    traces: &[TraceEntry],
    command: &str,
    colored_command: &str,
    result: &engine::EvalResult,
    display_path: &str,
    term: &output::Terminal,
) {
    if !traces.is_empty() {
        let _ = writeln!(w, "\n{}\n", "Trace".bold());
        output::write_trace(w, traces, command, "  ", term);
    }

    let _ = writeln!(w, "\n{}\n", "Result".bold());
    let _ = writeln!(w, "  {colored_command}");
    let _ = writeln!(w);
    {
        use may_i_pp::colorize_atom;
        let keyword = format!(":{}", result.decision);
        let colored_keyword = output::colorize_decision_keyword(&keyword);
        match &result.reason {
            Some(reason) => {
                let quoted = format!("\"{reason}\"");
                let _ = writeln!(
                    w,
                    "  {} {colored_keyword} {}",
                    "→".dimmed(),
                    colorize_atom(&quoted, true)
                );
            }
            None => {
                let _ = writeln!(w, "  {} {colored_keyword}", "→".dimmed());
            }
        }
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "  {} {}", "config:".dimmed(), display_path.dimmed());
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

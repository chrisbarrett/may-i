// Eval subcommand — evaluate a command and print result with trace.

use std::io::Write;

use colored::Colorize;

use may_i_core::Decision;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;
use crate::runtime_facts::parse_cli_facts;

pub fn cmd_eval(
    command: &str,
    raw_facts: &[String],
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let loaded: crate::loaded_config::LoadedConfig =
        may_i_config::load_and_resolve(config_path)?.into();
    let config_file = &loaded.config_path;
    let context = parse_cli_facts(raw_facts)?;

    if json_mode {
        let mut fold = TracingFold::from_loaded_config(&loaded);
        let result =
            engine::eval::evaluate_command_with_fold(command, &loaded.config, &context, &mut fold)
                .map_err(|e| miette::miette!("{e}"))?;
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "trace": output::trace_to_json(&fold.traces),
        });
        println!(
            "{}",
            serde_json::to_string(&json).expect("response serialization is infallible")
        );
    } else {
        let term = output::Terminal::detect();
        if let Some(note) = output::migration_note(&loaded, config_file) {
            output::write_layout(&mut std::io::stderr(), &note, &term);
        }
        let (result, traces, colored_command) =
            evaluate_with_colorization(command, &loaded, &context)?;
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
    loaded: &crate::loaded_config::LoadedConfig,
    context: &may_i_core::ContextFacts,
) -> miette::Result<(engine::EvalResult, Vec<TraceEntry>, String)> {
    // Use the unified evaluation pipeline for the decision
    let mut fold = TracingFold::from_loaded_config(loaded);
    let result =
        engine::eval::evaluate_command_with_fold(command, &loaded.config, context, &mut fold)
            .map_err(|e| miette::miette!("{e}"))?;

    // Use segment() for display colorization only
    let segments = parser::segment(command);
    let colored_command = if segments.is_empty() {
        colorize_text(command, result.decision)
    } else {
        colorize_segments(command, &segments, loaded, context)
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

/// Colorize each segment independently for display.
fn colorize_segments(
    command: &str,
    segments: &[parser::Segment],
    loaded: &crate::loaded_config::LoadedConfig,
    context: &may_i_core::ContextFacts,
) -> String {
    let mut display_parts = Vec::new();
    for seg in segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            // Evaluate each segment for its color
            let decision = engine::eval::evaluate_command(text, &loaded.config, context)
                .map(|r| r.decision)
                .unwrap_or(Decision::Ask);
            display_parts.push(colorize_text(text, decision));
        }
    }
    display_parts.concat()
}

// Eval subcommand — evaluate a command and print result with trace.

use std::io::Write;

use colored::Colorize;

use may_i_config as config;
use may_i_core::Decision;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;
use crate::runtime_facts::parse_cli_facts;

/// Parse a simple command string into (command_name, args) using the shell
/// parser, which correctly handles quoting. Falls back to split_whitespace
/// for non-simple commands.
fn parse_command_args(text: &str) -> (String, Vec<String>) {
    match parser::parse(text) {
        parser::Command::Simple(sc) if !sc.words.is_empty() => {
            let cmd = sc.words[0].to_str();
            let args: Vec<String> = sc.words[1..].iter().map(|w| w.to_str()).collect();
            (cmd, args)
        }
        _ => {
            let cmd = text.split_whitespace().next().unwrap_or(text).to_string();
            let args: Vec<String> = text.split_whitespace().skip(1).map(String::from).collect();
            (cmd, args)
        }
    }
}

pub fn cmd_eval(
    command: &str,
    raw_facts: &[String],
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let mut config = config::load(&config_file)?;
    let context = parse_cli_facts(raw_facts)?;

    // Resolve named predicates before evaluation.
    let (resolved_rules, _) =
        may_i_config::resolve::validate_and_resolve(&config.rules, &config.defines)
            .map_err(|errs| miette::miette!("Predicate resolution failed: {}", errs[0].message))?;
    config.rules = resolved_rules;

    if json_mode {
        let mut fold = TracingFold::new()
            .with_source_text(config.source_text.clone())
            .with_pre_migration_forms(config.pre_migration_forms.clone());
        let (cmd, args) = parse_command_args(command);
        let result = engine::eval::evaluate_with_fold(&cmd, &args, &config, &context, &mut fold);
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
        let (result, traces, colored_command) = evaluate_segments(command, &config, &context);
        let display_path = output::shorten_home(&config_file);
        write_eval_output(
            &mut std::io::stdout(),
            &traces,
            &colored_command,
            &result,
            &display_path,
        );
    }

    Ok(())
}

/// Render trace + result output to a writer.
pub fn write_eval_output(
    w: &mut impl Write,
    traces: &[TraceEntry],
    colored_command: &str,
    result: &engine::EvalResult,
    display_path: &str,
) {
    if !traces.is_empty() {
        let _ = writeln!(w, "\n{}\n", "Trace".bold());
        output::write_trace(w, traces, "  ");
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

/// Evaluate each segment of a command, returning the aggregate result, traces,
/// and a colorized display string.
pub fn evaluate_segments(
    command: &str,
    config: &may_i_core::ast::Config,
    context: &may_i_core::ContextFacts,
) -> (engine::EvalResult, Vec<TraceEntry>, String) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        let mut fold = TracingFold::new()
            .with_source_text(config.source_text.clone())
            .with_pre_migration_forms(config.pre_migration_forms.clone());
        let (cmd, args) = parse_command_args(command);
        let result = engine::eval::evaluate_with_fold(&cmd, &args, config, context, &mut fold);
        return (result, fold.traces, command.to_string());
    }

    let mut display_parts = Vec::new();
    let mut cmd_evals: Vec<(&str, engine::EvalResult, Vec<TraceEntry>)> = Vec::new();

    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            let mut fold = TracingFold::new()
                .with_source_text(config.source_text.clone())
                .with_pre_migration_forms(config.pre_migration_forms.clone());
            let (cmd, args) = parse_command_args(text);
            let result = engine::eval::evaluate_with_fold(&cmd, &args, config, context, &mut fold);
            let colored = match result.decision {
                Decision::Allow => text.green().underline().to_string(),
                Decision::Ask => text.yellow().underline().to_string(),
                Decision::Deny => text.red().underline().to_string(),
            };
            display_parts.push(colored);
            cmd_evals.push((text, result, fold.traces));
        }
    }

    let multi_segment = cmd_evals.len() > 1;
    let mut traces = Vec::new();
    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason = None;

    for (text, eval, segment_traces) in &cmd_evals {
        if multi_segment {
            traces.push(TraceEntry::SegmentHeader {
                command: text.to_string(),
                decision: eval.decision,
            });
        }
        traces.extend(segment_traces.iter().cloned());
        if eval.decision >= aggregate_decision {
            aggregate_decision = eval.decision;
            aggregate_reason = eval.reason.clone();
        }
    }

    let result = engine::EvalResult::new(aggregate_decision, aggregate_reason);
    (result, traces, display_parts.concat())
}

// Eval subcommand — evaluate a command and print result with trace.

use colored::Colorize;

use may_i_config as config;
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
    let config_file = config::resolve_path(config_path)?;
    let mut config = config::load(&config_file)?;
    let context = parse_cli_facts(raw_facts)?;

    // Resolve named predicates before evaluation.
    let (resolved_rules, _) =
        may_i_config::resolve::validate_and_resolve(&config.rules, &config.defines)
            .map_err(|errs| miette::miette!("Predicate resolution failed: {}", errs[0].message))?;
    config.rules = resolved_rules;

    if json_mode {
        let mut fold = TracingFold::new().with_source_text(config.source_text.clone());
        let args: Vec<String> = command
            .split_whitespace()
            .skip(1)
            .map(String::from)
            .collect();
        let cmd = command.split_whitespace().next().unwrap_or(command);
        let result = engine::eval::evaluate_with_fold(cmd, &args, &config, &context, &mut fold);
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

        if !traces.is_empty() {
            println!("\n{}\n", "Trace".bold());
            output::print_trace(&traces, "  ");
        }

        println!("\n{}\n", "Result".bold());
        println!("  {colored_command}");
        println!();
        {
            use may_i_pp::colorize_atom;
            let keyword = format!(":{}", result.decision);
            let colored_keyword = output::colorize_decision_keyword(&keyword);
            match &result.reason {
                Some(reason) => {
                    let quoted = format!("\"{reason}\"");
                    println!(
                        "  {} {colored_keyword} {}",
                        "→".dimmed(),
                        colorize_atom(&quoted, true)
                    );
                }
                None => println!("  {} {colored_keyword}", "→".dimmed()),
            }
        }
        println!();
        let display_path = output::shorten_home(&config_file);
        println!("  {} {}", "config:".dimmed(), display_path.dimmed());
    }

    Ok(())
}

/// Evaluate each segment of a command, returning the aggregate result, traces,
/// and a colorized display string.
fn evaluate_segments(
    command: &str,
    config: &may_i_core::ast::Config,
    context: &may_i_core::ContextFacts,
) -> (engine::EvalResult, Vec<TraceEntry>, String) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        let mut fold = TracingFold::new().with_source_text(config.source_text.clone());
        let args: Vec<String> = command
            .split_whitespace()
            .skip(1)
            .map(String::from)
            .collect();
        let cmd = command.split_whitespace().next().unwrap_or(command);
        let result = engine::eval::evaluate_with_fold(cmd, &args, config, context, &mut fold);
        return (result, fold.traces, command.to_string());
    }

    let mut display_parts = Vec::new();
    let mut cmd_evals: Vec<(&str, engine::EvalResult, Vec<TraceEntry>)> = Vec::new();

    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            let mut fold = TracingFold::new().with_source_text(config.source_text.clone());
            let args: Vec<String> = text.split_whitespace().skip(1).map(String::from).collect();
            let cmd = text.split_whitespace().next().unwrap_or(text);
            let result = engine::eval::evaluate_with_fold(cmd, &args, config, context, &mut fold);
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
        if eval.decision > aggregate_decision {
            aggregate_decision = eval.decision;
            aggregate_reason = eval.reason.clone();
        }
    }

    let result = engine::EvalResult::new(aggregate_decision, aggregate_reason);
    (result, traces, display_parts.concat())
}

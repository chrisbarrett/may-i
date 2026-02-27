// Eval subcommand — evaluate a command and print result.

use colored::Colorize;

use may_i_core::Decision;
use may_i_config as config;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::output;
use crate::output::print_trace;

pub fn cmd_eval(
    command: &str,
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config = config::load(config_path)?;

    if json_mode {
        let result = engine::evaluate(command, &config);
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "trace": crate::output::trace_to_json(&result.trace),
        });
        println!("{}", serde_json::to_string(&json).expect("response serialization is infallible"));
    } else {
        // Evaluate per-segment so we can both colorize and derive the aggregate result.
        let (result, colored_command) = evaluate_segments(command, &config);

        if !result.trace.is_empty() {
            println!("\n{}\n", "Trace".bold());
            print_trace(&result.trace, "  ");
        }

        println!("\n{}\n", "Command".bold());
        println!("  {colored_command}");

        println!("\n{}\n", "Result".bold());
        {
            use may_i_pp::colorize_atom;
            let keyword = format!(":{}", result.decision);
            let colored_keyword = output::colorize_decision_keyword(&keyword);
            match &result.reason {
                Some(reason) => {
                    let quoted = format!("\"{reason}\"");
                    println!("  {colored_keyword} {}", colorize_atom(&quoted, true));
                }
                None => println!("  {colored_keyword}"),
            }
        }
        println!();
    }

    Ok(())
}

/// Evaluate each segment of a command, returning the aggregate result and a
/// colorized display string. This avoids evaluating the entire command twice.
fn evaluate_segments(
    command: &str,
    config: &may_i_core::Config,
) -> (may_i_core::EvalResult, String) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        return (engine::evaluate(command, config), command.to_string());
    }

    // Evaluate each command segment, collecting (text, result) pairs.
    let mut display_parts = Vec::new();
    let mut cmd_evals: Vec<(&str, may_i_core::EvalResult)> = Vec::new();
    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            let seg_result = engine::evaluate(text, config);
            let colored = match seg_result.decision {
                Decision::Allow => text.green().underline().to_string(),
                Decision::Ask => text.yellow().underline().to_string(),
                Decision::Deny => text.red().underline().to_string(),
            };
            display_parts.push(colored);
            cmd_evals.push((text, seg_result));
        }
    }

    let multi_segment = cmd_evals.len() > 1;

    // Build aggregate trace with segment headers for compound commands.
    let mut trace = Vec::new();
    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason = None;

    for (text, eval) in &cmd_evals {
        if multi_segment {
            trace.push(may_i_core::TraceStep::SegmentHeader {
                command: text.to_string(),
                decision: eval.decision,
            });
        }
        trace.extend(eval.trace.iter().cloned());
        if eval.decision > aggregate_decision {
            aggregate_decision = eval.decision;
            aggregate_reason = eval.reason.clone();
        }
    }

    let result = may_i_core::EvalResult {
        decision: aggregate_decision,
        reason: aggregate_reason,
        trace,
    };

    (result, display_parts.concat())
}

// Eval subcommand — evaluate a command and print result.

use colored::Colorize;

use may_i_core::{Decision, LoadError};
use may_i_config as config;
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::output::print_trace;

pub fn cmd_eval(
    command: &str,
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> Result<(), LoadError> {
    let config = config::load(config_path)?;

    if json_mode {
        let result = engine::evaluate(command, &config);
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "trace": result.trace,
        });
        println!("{}", serde_json::to_string(&json).expect("response serialization is infallible"));
    } else {
        // Evaluate per-segment so we can both colorize and derive the aggregate result.
        let (result, colored_command) = evaluate_segments(command, &config);

        println!("\n{}\n", "Command".bold());
        println!("  {colored_command}");

        println!("\n{}\n", "Result".bold());
        {
            use may_i_pp::{Doc, Format, pretty};
            let mut children = vec![Doc::atom(format!(":{}", result.decision))];
            if let Some(reason) = &result.reason {
                children.push(Doc::atom(format!("\"{reason}\"")));
            }
            let doc = Doc::list(children);
            let formatted = pretty(&doc, 2, &Format::colored());
            for line in formatted.lines() {
                println!("  {line}");
            }
        }
        if !result.trace.is_empty() {
            println!("\n{}\n", "Trace".bold());
            print_trace(&result.trace, "  ");
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

    let mut parts = Vec::new();
    let mut seg_results = Vec::new();
    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            parts.push(format!(" {text} "));
        } else {
            let seg_result = engine::evaluate(text, config);
            let colored = match seg_result.decision {
                Decision::Allow => text.green().underline().to_string(),
                Decision::Ask => text.yellow().underline().to_string(),
                Decision::Deny => text.red().underline().to_string(),
            };
            parts.push(colored);
            seg_results.push(seg_result);
        }
    }

    // Aggregate: most restrictive segment wins.
    let result = seg_results.into_iter().reduce(|acc, r| {
        let decision = acc.decision.most_restrictive(r.decision);
        let reason = if decision == r.decision { r.reason } else { acc.reason };
        let mut trace = acc.trace;
        trace.extend(r.trace);
        may_i_core::EvalResult { decision, reason, trace }
    }).unwrap_or_else(|| engine::evaluate(command, config));

    (result, parts.concat())
}

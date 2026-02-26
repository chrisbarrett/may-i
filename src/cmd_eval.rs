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
    let result = engine::evaluate(command, &config);

    if json_mode {
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "trace": result.trace,
        });
        println!("{}", serde_json::to_string(&json).unwrap());
    } else {
        println!("\n{}\n", "Command".bold());
        print!("  ");
        print_colored_command(command, &config);
        println!();

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

fn print_colored_command(command: &str, config: &may_i_core::Config) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        println!("{command}");
        return;
    }

    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            print!(" {text} ");
        } else {
            let seg_result = engine::evaluate(text, config);
            let colored = match seg_result.decision {
                Decision::Allow => text.on_truecolor(0, 80, 0).to_string(),
                Decision::Ask => text.on_truecolor(120, 100, 0).to_string(),
                Decision::Deny => text.on_truecolor(120, 0, 0).to_string(),
            };
            print!("{colored}");
        }
    }
    println!();
}

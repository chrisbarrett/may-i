// Eval subcommand — evaluate a command and print result.

use colored::Colorize;

use may_i_config as config;

use crate::runtime_facts::parse_cli_facts;

pub fn cmd_eval(
    command: &str,
    raw_facts: &[String],
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let context = parse_cli_facts(raw_facts)?;

    let canonical_config = config::load(&config_file)?;
    let args: Vec<String> = command
        .split_whitespace()
        .skip(1)
        .map(String::from)
        .collect();
    let cmd = command.split_whitespace().next().unwrap_or(command);
    let result = may_i_engine::eval::evaluate(cmd, &args, &canonical_config, &context);

    if json_mode {
        println!(
            "{}",
            serde_json::json!({
                "decision": result.decision.to_string(),
                "reason": result.reason.clone().unwrap_or_default(),
            })
        );
    } else {
        println!("{}: {:?}", "Decision".bold(), result.decision);
        if let Some(reason) = &result.reason {
            println!("{}: {}", "Reason".bold(), reason);
        }
    }

    Ok(())
}

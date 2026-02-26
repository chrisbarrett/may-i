// Hook mode — read Claude Code hook payload from stdin, evaluate, respond.

use std::io::Read;

use miette::Context;
use may_i_config as config;
use may_i_engine as engine;

pub fn cmd_hook(config_path: Option<&std::path::Path>) -> miette::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Failed to read stdin")?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Invalid JSON")?;

    // If tool is not "Bash", exit silently (allow the call)
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if tool_name != "Bash" {
        return Ok(());
    }

    let command = payload
        .get("tool_input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| miette::miette!("Missing tool_input.command"))?;

    let config = config::load(config_path)?;
    let result = engine::evaluate(command, &config);

    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": result.decision.to_string(),
            "permissionDecisionReason": result.reason.unwrap_or_default()
        }
    });

    println!("{}", serde_json::to_string(&response).expect("response serialization is infallible"));
    Ok(())
}

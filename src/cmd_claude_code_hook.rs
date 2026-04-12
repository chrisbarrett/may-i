// Hook mode — read Claude Code hook payload from stdin, evaluate, respond.

use std::io::Read;

use may_i_config as config;
use may_i_core::{ContextFacts, Keyword};
use may_i_engine as engine;
use may_i_engine::EvalResult;
use miette::Context;

pub(crate) fn cmd_claude_code_hook(config_path: Option<&std::path::Path>) -> miette::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Failed to read stdin")?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Invalid JSON")?;

    // Extract command from payload; None means silent (non-Bash tool)
    let Some(command) = extract_command(&payload)? else {
        return Ok(());
    };

    let loaded = config::load_and_resolve(config_path)?;

    let context = build_context(&payload);
    let result = engine::eval::evaluate_command(&command, &loaded.config, &context)
        .map_err(|e| miette::miette!("{e}"))?;

    let response = render_response(result);

    println!(
        "{}",
        serde_json::to_string(&response).expect("response serialization is infallible")
    );
    Ok(())
}

/// Extract the command from the hook payload.
/// Returns None for non-Bash tools (silent handling).
/// Returns Err if tool_name is missing or Bash tool is missing required command field.
fn extract_command(payload: &serde_json::Value) -> miette::Result<Option<String>> {
    let Some(tool_name) = payload.get("tool_name").and_then(|v| v.as_str()) else {
        return Err(miette::miette!(
            "Unrecognized hook payload; no registered harness matched the input"
        ));
    };

    if tool_name != "Bash" {
        // Non-Bash tools are handled silently
        return Ok(None);
    }

    let command = payload
        .get("tool_input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| miette::miette!("Missing tool_input.command"))?;

    Ok(Some(command.to_string()))
}

/// Build context facts from the hook payload.
fn build_context(payload: &serde_json::Value) -> ContextFacts {
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Bash");

    let mut context = ContextFacts::default();
    context
        .insert_present(Keyword::new(":client/claude-code").expect("hardcoded keyword is valid"));

    if let Some(permission_mode) = payload.get("permission_mode").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(":claude-code/permission-mode").expect("hardcoded keyword is valid"),
            permission_mode,
        );
    }
    if let Some(cwd) = payload.get("cwd").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(":claude-code/cwd").expect("hardcoded keyword is valid"),
            cwd,
        );
    }
    context.insert_scalar(
        Keyword::new(":claude-code/tool-name").expect("hardcoded keyword is valid"),
        tool_name,
    );
    if let Some(event_name) = payload.get("hook_event_name").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(":claude-code/hook-event-name").expect("hardcoded keyword is valid"),
            event_name,
        );
    }

    context
}

/// Render the evaluation result in Claude Code hook response format.
fn render_response(result: EvalResult) -> serde_json::Value {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": result.decision.to_string(),
            "permissionDecisionReason": result.reason.unwrap_or_default(),
        }
    })
}

use may_i_core::{ContextFacts, EvalResult};

pub enum HookRoute {
    Silent,
    Evaluate {
        command: String,
        context: ContextFacts,
        harness: Harness,
    },
}

pub enum Harness {
    ClaudeCode,
}

impl Harness {
    pub fn render_response(&self, result: EvalResult) -> serde_json::Value {
        match self {
            Harness::ClaudeCode => serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": result.decision.to_string(),
                    "permissionDecisionReason": result.reason.unwrap_or_default(),
                }
            }),
        }
    }
}

pub fn route_hook(payload: &serde_json::Value) -> miette::Result<HookRoute> {
    if let Some(route) = try_route_claude_code(payload)? {
        return Ok(route);
    }

    Err(miette::miette!(
        "Unrecognized hook payload; no registered harness matched the input"
    ))
}

fn try_route_claude_code(payload: &serde_json::Value) -> miette::Result<Option<HookRoute>> {
    let Some(tool_name) = payload.get("tool_name").and_then(|value| value.as_str()) else {
        return Ok(None);
    };

    if tool_name != "Bash" {
        return Ok(Some(HookRoute::Silent));
    }

    let command = payload
        .get("tool_input")
        .and_then(|value| value.get("command"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| miette::miette!("Missing tool_input.command"))?;

    let mut context = ContextFacts::default();
    context.insert_present(":client/claude-code");
    if let Some(permission_mode) = payload
        .get("permission_mode")
        .and_then(|value| value.as_str())
    {
        context.insert_scalar(":claude-code/permission-mode", permission_mode);
    }
    if let Some(cwd) = payload.get("cwd").and_then(|value| value.as_str()) {
        context.insert_scalar(":claude-code/cwd", cwd);
    }
    context.insert_scalar(":claude-code/tool-name", tool_name);
    if let Some(event_name) = payload
        .get("hook_event_name")
        .and_then(|value| value.as_str())
    {
        context.insert_scalar(":claude-code/hook-event-name", event_name);
    }

    Ok(Some(HookRoute::Evaluate {
        command: command.to_string(),
        context,
        harness: Harness::ClaudeCode,
    }))
}

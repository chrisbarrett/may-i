// Hook mode — read PreToolUse hook payload from stdin, select the
// harness profile, evaluate the command, and respond in the profile's
// JSON shape. Profile selection is presence-based on the `turn_id`
// field; once chosen it is threaded through the pipeline so renderers
// can branch on it.

use std::io::Read;

use may_i_core::{ContextFacts, EntryEnv, Keyword};
use may_i_engine as engine;
use miette::Context;

use may_i::audit::AuditTap;
use may_i::pipeline::{CommandPipeline, HarnessProfile, HookOutcomeBody};

pub(crate) fn cmd_hook(pipeline: &mut CommandPipeline) -> miette::Result<()> {
    // Capture the entry environment as the very first action — the names-only
    // snapshot of the exported environment — before any internal mutation.
    // The git-environment scrubbing (`io.rs`) only edits spawned child
    // `Command`s, never this process's `std::env`, so a name exported at entry
    // (e.g. `GIT_DIR`) survives in this snapshot.
    let entry_env = EntryEnv::from_names(std::env::vars().map(|(name, _value)| name));

    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))
        .wrap_err("Failed to read stdin")?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))
        .wrap_err("Invalid JSON")?;

    let Some(command) = extract_command(&payload)? else {
        return Ok(());
    };

    let profile = HarnessProfile::from_payload(&payload);
    let context = build_context(&payload, profile);
    let cwd = payload
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    pipeline.run_hook(&command, profile, |ctx| {
        // Hook runs `AuditFold` alone — no trace-tree cost on the hot path.
        let mut fold = engine::AuditFold::new();
        let result = engine::eval::evaluate_command_with_fold_env(
            &command, ctx.config, &context, &entry_env, &mut fold,
        )
        .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))?;
        let audit_rules = fold.into_deciding_hashes(result.decision);
        let audit = AuditTap::from_eval(&result, &command, audit_rules, cwd.clone());
        Ok(HookOutcomeBody { result, audit })
    })
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
        return Ok(None);
    }

    let command = payload
        .get("tool_input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| miette::miette!("Missing tool_input.command"))?;

    Ok(Some(command.to_string()))
}

/// Build context facts from the hook payload. Exactly one client fact
/// (`:client/claude-code` or `:client/codex`) is inserted per invocation,
/// determined by `profile`; the per-harness secondary fields use the
/// matching namespace.
fn build_context(payload: &serde_json::Value, profile: HarnessProfile) -> ContextFacts {
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Bash");

    let (client_key, ns) = match profile {
        HarnessProfile::ClaudeCode => (":client/claude-code", "claude-code"),
        HarnessProfile::Codex => (":client/codex", "codex"),
    };

    let mut context = ContextFacts::default();
    context.insert_present(Keyword::new(client_key).expect("hardcoded keyword is valid"));
    context.insert_present(Keyword::new(":tool/bash").expect("hardcoded keyword is valid"));

    if let Some(permission_mode) = payload.get("permission_mode").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(format!(":{ns}/permission-mode")).expect("hardcoded keyword is valid"),
            permission_mode,
        );
    }
    if let Some(cwd) = payload.get("cwd").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(format!(":{ns}/cwd")).expect("hardcoded keyword is valid"),
            cwd,
        );
    }
    context.insert_scalar(
        Keyword::new(format!(":{ns}/tool-name")).expect("hardcoded keyword is valid"),
        tool_name,
    );
    if let Some(event_name) = payload.get("hook_event_name").and_then(|v| v.as_str()) {
        context.insert_scalar(
            Keyword::new(format!(":{ns}/hook-event-name")).expect("hardcoded keyword is valid"),
            event_name,
        );
    }

    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_defaults_to_claude_code_without_turn_id() {
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        });
        assert_eq!(HarnessProfile::from_payload(&p), HarnessProfile::ClaudeCode);
    }

    #[test]
    fn profile_is_codex_when_turn_id_is_string() {
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "turn_id": "t-1",
        });
        assert_eq!(HarnessProfile::from_payload(&p), HarnessProfile::Codex);
    }

    #[test]
    fn profile_is_codex_when_turn_id_is_null() {
        // Presence semantics: a key whose value is null still counts.
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "turn_id": null,
        });
        assert_eq!(HarnessProfile::from_payload(&p), HarnessProfile::Codex);
    }

    #[test]
    fn claude_code_context_carries_claude_code_facts() {
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "cwd": "/repo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
        });
        let ctx = build_context(&p, HarnessProfile::ClaudeCode);
        let cc = Keyword::new(":client/claude-code").unwrap();
        let cx = Keyword::new(":client/codex").unwrap();
        assert!(ctx.has(&cc));
        assert!(!ctx.has(&cx));
        assert!(
            ctx.get_scalar(&Keyword::new(":claude-code/cwd").unwrap())
                .is_some()
        );
        assert!(
            ctx.get_scalar(&Keyword::new(":codex/cwd").unwrap())
                .is_none()
        );
    }

    #[test]
    fn tool_bash_fact_is_present_under_both_profiles() {
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        });
        let tool_bash = Keyword::new(":tool/bash").unwrap();
        assert!(build_context(&p, HarnessProfile::ClaudeCode).has(&tool_bash));
        assert!(build_context(&p, HarnessProfile::Codex).has(&tool_bash));
    }

    #[test]
    fn codex_context_carries_codex_facts() {
        let p = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "cwd": "/repo",
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "turn_id": "t-1",
        });
        let ctx = build_context(&p, HarnessProfile::Codex);
        let cx = Keyword::new(":client/codex").unwrap();
        let cc = Keyword::new(":client/claude-code").unwrap();
        assert!(ctx.has(&cx));
        assert!(!ctx.has(&cc));
        assert!(
            ctx.get_scalar(&Keyword::new(":codex/cwd").unwrap())
                .is_some()
        );
        assert!(
            ctx.get_scalar(&Keyword::new(":codex/permission-mode").unwrap())
                .is_some()
        );
        assert!(
            ctx.get_scalar(&Keyword::new(":claude-code/cwd").unwrap())
                .is_none()
        );
    }
}

// CLI interface — R1, R2, R3, R4

use std::io::Read;

use crate::config;
use crate::engine;
use crate::types::{Config, Decision};

/// Main entry point for the CLI.
pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("eval") => cmd_eval(&args[2..]),
        Some("check") => cmd_check(),
        _ => cmd_hook(),
    }
}

/// R1: Hook mode — read Claude Code hook payload from stdin, evaluate, respond.
fn cmd_hook() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| format!("Failed to read stdin: {e}"))?;

    let payload: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON: {e}"))?;

    // If type is not "Bash", exit silently
    let tool_type = payload
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if tool_type != "Bash" {
        return Ok(());
    }

    let command = payload
        .get("tool_input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .ok_or("Missing tool_input.command")?;

    let config = config::load()?;
    let result = engine::evaluate(command, &config);

    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": result.decision.to_string(),
            "permissionDecisionReason": result.reason.unwrap_or_default()
        }
    });

    println!("{}", serde_json::to_string(&response).unwrap());
    Ok(())
}

/// R2: Eval subcommand — evaluate a command and print result.
fn cmd_eval(args: &[String]) -> Result<(), String> {
    let json_mode = args.first().is_some_and(|a| a == "--json");
    let cmd_args = if json_mode { &args[1..] } else { args };

    let command = cmd_args.first().ok_or("Usage: may-i eval [--json] '<command>'")?;

    let config = config::load()?;
    let result = engine::evaluate(command, &config);

    if json_mode {
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default()
        });
        println!("{}", serde_json::to_string(&json).unwrap());
    } else {
        let reason = result.reason.as_deref().unwrap_or("");
        if reason.is_empty() {
            println!("{}", result.decision);
        } else {
            println!("{}: {reason}", result.decision);
        }
    }

    Ok(())
}

/// R3: Check subcommand — validate config and run examples.
fn cmd_check() -> Result<(), String> {
    let config = config::load()?;
    let results = check_examples(&config);

    let mut passed = 0;
    let mut failed = 0;

    for r in &results {
        if r.passed {
            passed += 1;
            println!("  PASS: {} → {}", r.command, r.actual);
        } else {
            failed += 1;
            println!("  FAIL: {} → {} (expected {})", r.command, r.actual, r.expected);
        }
    }

    println!("\n{passed} passed, {failed} failed");

    if failed > 0 {
        Err(format!("{failed} example(s) failed"))
    } else {
        Ok(())
    }
}

/// Run all embedded examples from config rules and compare against expected decisions.
fn check_examples(config: &Config) -> Vec<ExampleResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for example in &rule.examples {
            let eval = engine::evaluate(&example.command, config);
            results.push(ExampleResult {
                command: example.command.clone(),
                expected: example.expected,
                actual: eval.decision,
                passed: eval.decision == example.expected,
            });
        }
    }

    results
}

#[derive(Debug)]
struct ExampleResult {
    command: String,
    expected: Decision,
    actual: Decision,
    passed: bool,
}

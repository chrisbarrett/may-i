// CLI interface — clap derive with TTY detection

use std::io::{IsTerminal, Read};

use clap::{CommandFactory, Parser, Subcommand};

use may_i::check;
use may_i::config;
use may_i::engine;
use may_i::parser;

#[derive(Parser)]
#[command(name = "may-i", version, about = "Shell command authorization evaluator")]
struct Cli {
    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a shell command against the loaded config
    Eval { command: String },
    /// Validate config and run all embedded checks
    Check,
    /// Parse a shell command and print the AST
    Parse {
        command: Option<String>,
        /// Read command from a file (use `-` for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        // Exit code 2 signals a blocking error to Claude Code hooks.
        // stderr is fed back to Claude so it can adjust its plan.
        std::process::exit(2);
    }
}

/// Main entry point for the CLI.
fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Eval { command }) => cmd_eval(&command, cli.json),
        Some(Command::Check) => cmd_check(cli.json),
        Some(Command::Parse { command, file }) => cmd_parse(command, file),
        None => {
            if std::io::stdin().is_terminal() {
                Cli::command()
                    .print_help()
                    .map_err(|e| format!("Failed to print help: {e}"))?;
                println!();
                Ok(())
            } else {
                cmd_hook()
            }
        }
    }
}

/// Hook mode — read Claude Code hook payload from stdin, evaluate, respond.
fn cmd_hook() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| format!("Failed to read stdin: {e}"))?;

    let payload: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON: {e}"))?;

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

/// Eval subcommand — evaluate a command and print result.
fn cmd_eval(command: &str, json_mode: bool) -> Result<(), String> {
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

/// Check subcommand — validate config and run checks.
fn cmd_check(json_mode: bool) -> Result<(), String> {
    let config = config::load()?;
    let results = check::run_checks(&config);

    let mut passed = 0;
    let mut failed = 0;

    if json_mode {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                if r.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
                serde_json::json!({
                    "command": r.command,
                    "expected": r.expected.to_string(),
                    "actual": r.actual.to_string(),
                    "passed": r.passed
                })
            })
            .collect();

        let output = serde_json::json!({
            "passed": passed,
            "failed": failed,
            "results": json_results
        });
        println!("{}", serde_json::to_string(&output).unwrap());
    } else {
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
    }

    if failed > 0 {
        Err(format!("{failed} check(s) failed"))
    } else {
        Ok(())
    }
}

/// Parse subcommand — parse a shell command and print the AST.
fn cmd_parse(command: Option<String>, file: Option<String>) -> Result<(), String> {
    let input = if let Some(path) = file {
        if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("Failed to read stdin: {e}"))?;
            buf
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {path}: {e}"))?
        }
    } else if let Some(cmd) = command {
        cmd
    } else {
        return Err("Usage: may-i parse '<command>' or may-i parse -f <file>".to_string());
    };

    let ast = parser::parse(&input);
    println!("{ast:#?}");
    Ok(())
}


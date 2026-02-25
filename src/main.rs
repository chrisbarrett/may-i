// CLI interface — clap derive with TTY detection

use std::io::{IsTerminal, Read};

use clap::{CommandFactory, Parser, Subcommand};
use colored::Colorize;

use may_i::check;
use may_i::config;
use may_i::engine;
use may_i::errors::LoadError;
use may_i::parser;

#[derive(Parser)]
#[command(name = "may-i", version, about = "Shell command authorization evaluator")]
struct Cli {
    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Path to config file (overrides $MAYI_CONFIG and default location)
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a shell command against the loaded config
    Eval { command: String },
    /// Validate config and run all embedded checks
    Check {
        /// Show passing checks (not just failures)
        #[arg(short, long)]
        verbose: bool,
    },
    /// Parse a shell command and print the AST
    Parse {
        command: Option<String>,
        /// Read command from a file (use `-` for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}

fn main() {
    miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(false)
                .build(),
        )
    }))
    .ok();

    if let Err(e) = run() {
        eprintln!("{e:?}");
        // Exit code 2 signals a blocking error to Claude Code hooks.
        // stderr is fed back to Claude so it can adjust its plan.
        std::process::exit(2);
    }
}

/// Main entry point for the CLI.
fn run() -> miette::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Eval { command }) => cmd_eval(&command, cli.json, cli.config.as_deref())?,
        Some(Command::Check { verbose }) => cmd_check(cli.json, verbose, cli.config.as_deref())?,
        Some(Command::Parse { command, file }) => cmd_parse(command, file)?,
        None => {
            if std::io::stdin().is_terminal() {
                Cli::command()
                    .print_help()
                    .map_err(|e| miette::miette!("Failed to print help: {e}"))?;
                println!();
            } else {
                cmd_hook(cli.config.as_deref())?;
            }
        }
    }

    Ok(())
}

/// Hook mode — read Claude Code hook payload from stdin, evaluate, respond.
fn cmd_hook(config_path: Option<&std::path::Path>) -> Result<(), LoadError> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| LoadError::Io(format!("Failed to read stdin: {e}")))?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| LoadError::Io(format!("Invalid JSON: {e}")))?;

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
        .ok_or_else(|| LoadError::Io("Missing tool_input.command".into()))?;

    let config = config::load(config_path)?;
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
fn cmd_eval(
    command: &str,
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> Result<(), LoadError> {
    let config = config::load(config_path)?;
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
fn cmd_check(json_mode: bool, verbose: bool, config_path: Option<&std::path::Path>) -> Result<(), LoadError> {
    let config = config::load(config_path)?;
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
                    "passed": r.passed,
                    "location": r.location,
                    "reason": r.reason,
                    "trace": r.trace,
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
        let mut failures = Vec::new();

        for r in &results {
            if r.passed {
                passed += 1;
                if verbose {
                    println!("  {} {}", "PASS".green().bold(), format!("{} → {}", r.command, r.actual).dimmed());
                }
            } else {
                failed += 1;
                if verbose {
                    println!("  {} {}", "FAIL".red().bold(), format!("{} → {} (expected {})", r.command, r.actual, r.expected).truecolor(255, 165, 0));
                }
                failures.push(r);
            }
        }

        if !failures.is_empty() {
            println!("\n{}\n", "Failures".bold());
            for r in &failures {
                let loc = r.location.as_deref().unwrap_or("<unknown>");
                let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
                print!("{}", file.red());
                if !line_col.is_empty() {
                    print!("{}", format!(":{line_col}").dimmed());
                }
                println!(": {}", r.command.bold());
                println!("  expected: {}", r.expected.to_string().green());
                println!("  actual:   {}", r.actual.to_string().red());
                if let Some(reason) = &r.reason {
                    println!("  reason:   {}", reason.italic());
                }
                if !r.trace.is_empty() {
                    println!("  trace:");
                    for step in &r.trace {
                        println!("    {step}");
                    }
                }
                println!();
            }
        }

        println!("{}\n", "Summary".bold());
        println!("  {passed} passed, {failed} failed");
    }

    if failed > 0 {
        Err(LoadError::Io(format!("{failed} check(s) failed")))
    } else {
        Ok(())
    }
}

/// Parse subcommand — parse a shell command and print the AST.
fn cmd_parse(command: Option<String>, file: Option<String>) -> miette::Result<()> {
    let input = if let Some(path) = file {
        if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| miette::miette!("Failed to read stdin: {e}"))?;
            buf
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| miette::miette!("Failed to read {path}: {e}"))?
        }
    } else if let Some(cmd) = command {
        cmd
    } else {
        return Err(miette::miette!(
            "Usage: may-i parse '<command>' or may-i parse -f <file>"
        ));
    };

    let ast = parser::parse(&input);
    println!("{ast:#?}");
    Ok(())
}

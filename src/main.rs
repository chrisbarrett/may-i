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
            use may_i::pp::{Doc, Format, pretty};
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

/// Print the command with background colors indicating decision levels.
fn print_colored_command(command: &str, config: &may_i::types::Config) {
    use colored::Colorize;
    use may_i::types::Decision;

    let segments = parser::segment(command);

    if segments.is_empty() {
        // No segments (e.g., empty command) — just print as-is
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
                    print_trace(&r.trace, "    ");
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

/// Print trace steps with aligned `=>` columns and horizontal rules under headings.
fn print_trace(steps: &[String], indent: &str) {
    use colored::Colorize;
    use std::collections::HashMap;

    // Compute arrow alignment per indentation depth, using median to avoid outliers.
    let mut positions_by_depth: HashMap<usize, Vec<usize>> = HashMap::new();
    for step in steps {
        let depth = step.len() - step.trim_start().len();
        if let Some(pos) = step.rfind(" => ") {
            positions_by_depth.entry(depth).or_default().push(pos);
        }
    }
    let arrow_by_depth: HashMap<usize, usize> = positions_by_depth.into_iter().map(|(depth, mut positions)| {
        positions.sort();
        // Use first quartile to avoid long lines dominating alignment.
        let idx = (positions.len().saturating_sub(1)) / 4;
        (depth, positions[idx])
    }).collect();

    // Track heading state: (start_depth, arrow_col, paren_balance).
    let mut heading: Option<(usize, usize, i32)> = None;
    let mut first_rule = true;

    for step in steps {
        let trimmed = step.trim_start();
        let depth = step.len() - trimmed.len();
        let arrow_col = arrow_by_depth.get(&depth).copied().unwrap_or(0);

        // Detect heading starts. Rule lines may have a "N: " line number prefix.
        let is_rule_heading = trimmed.starts_with("rule ")
            || trimmed.split_once(": ").is_some_and(|(n, rest)| {
                n.chars().all(|c| c.is_ascii_digit()) && rest.starts_with("rule ")
            });
        let is_heading_start = is_rule_heading || trimmed == "cond"
            || trimmed.starts_with("cond vs ");

        if is_heading_start && heading.is_none() {
            if is_rule_heading && !first_rule {
                println!();
            }
            if is_rule_heading {
                first_rule = false;
            }
            heading = Some((depth, arrow_col, 0));
        }

        // Track paren balance for multi-line headings.
        if let Some((_, _, ref mut balance)) = heading {
            for ch in step.chars() {
                if ch == '(' { *balance += 1; }
                if ch == ')' { *balance -= 1; }
            }
        }

        // Multi-line steps: print each line.
        for sub_line in step.split('\n') {
            println!("{indent}{}", colorize_trace_step(sub_line, arrow_col));
        }

        // Place horizontal rule after the heading is complete (parens balanced or no parens).
        if let Some((rule_depth, rule_arrow, balance)) = heading
            && balance <= 0
        {
            let rule_width = (rule_arrow + 20).max(rule_depth + 40) - rule_depth;
            let step_indent_str = " ".repeat(rule_depth);
            println!("{indent}{step_indent_str}{}", "─".repeat(rule_width).dimmed());
            heading = None;
        }
    }
}

/// Colorize a trace step: dim `=>` arrows, green `yes`, yellow `no`, italic `vs`.
/// Pads the left side of `=>` to align at `arrow_col`.
fn colorize_trace_step(step: &str, arrow_col: usize) -> String {
    use colored::Colorize;
    // Italicize " vs " separators
    let step = step.replace(" vs ", &format!(" {} ", "vs".italic()));
    if let Some(pos) = step.rfind(" => ") {
        let (before, rest) = step.split_at(pos);
        let after = &rest[4..]; // skip " => "
        // Pad before to align the arrow at arrow_col
        let visible_len = strip_ansi_len(before);
        let padding = arrow_col.saturating_sub(visible_len);
        let arrow = " => ".dimmed();
        let colored_after = if let Some(rest) = after.strip_prefix("yes") {
            format!("{}{rest}", "yes".green().bold())
        } else if let Some(rest) = after.strip_prefix("no") {
            format!("{}{rest}", "no".yellow())
        } else {
            after.to_string()
        };
        format!("{before}{:>pad$}{arrow}{colored_after}", "", pad = padding)
    } else {
        step.to_string()
    }
}

/// Get the visible (non-ANSI) length of a string.
fn strip_ansi_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
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

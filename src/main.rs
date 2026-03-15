// CLI interface — clap derive with TTY detection

use std::io::IsTerminal;

use clap::{CommandFactory, Parser, Subcommand};

mod cmd_check;
mod cmd_claude_code_hook;
mod cmd_eval;
mod cmd_parse;
mod output;
mod runtime_facts;

#[derive(Parser)]
#[command(
    name = "may-i",
    version,
    about = "Shell command authorization evaluator"
)]
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
    Eval {
        /// Add a runtime fact as :key or :key=value
        #[arg(long = "fact", value_name = "FACT")]
        facts: Vec<String>,
        command: String,
    },
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
        Box::new(miette::MietteHandlerOpts::new().build())
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
        Some(Command::Eval { command, facts }) => {
            cmd_eval::cmd_eval(&command, &facts, cli.json, cli.config.as_deref())?
        }
        Some(Command::Check { verbose }) => {
            cmd_check::cmd_check(cli.json, verbose, cli.config.as_deref())?
        }
        Some(Command::Parse { command, file }) => cmd_parse::cmd_parse(command, file, cli.json)?,
        None => {
            if std::io::stdin().is_terminal() {
                Cli::command()
                    .print_help()
                    .map_err(|e| miette::miette!("Failed to print help: {e}"))?;
                println!();
            } else {
                cmd_claude_code_hook::cmd_claude_code_hook(cli.config.as_deref())?;
            }
        }
    }

    Ok(())
}

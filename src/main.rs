// CLI interface — clap derive with TTY detection

use std::io::IsTerminal;

use clap::{CommandFactory, Parser, Subcommand};

mod cmd_eval;
mod cmd_check;
mod cmd_parse;
mod cmd_hook;


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
        Some(Command::Eval { command }) => cmd_eval::cmd_eval(&command, cli.json, cli.config.as_deref())?,
        Some(Command::Check { verbose }) => cmd_check::cmd_check(cli.json, verbose, cli.config.as_deref())?,
        Some(Command::Parse { command, file }) => cmd_parse::cmd_parse(command, file)?,
        None => {
            if std::io::stdin().is_terminal() {
                Cli::command()
                    .print_help()
                    .map_err(|e| miette::miette!("Failed to print help: {e}"))?;
                println!();
            } else {
                cmd_hook::cmd_hook(cli.config.as_deref())?;
            }
        }
    }

    Ok(())
}

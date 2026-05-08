// CLI interface — clap derive with TTY detection

use std::io::IsTerminal;

use clap::{CommandFactory, Parser, Subcommand};

mod cmd_claude_code_hook;
mod cmd_help;
mod cmd_migrate;
mod cmd_parse;

#[derive(Parser)]
#[command(
    name = "may-i",
    version,
    about = "Shell command authorization evaluator",
    long_about = "\
may-i evaluates shell commands against a policy you define, returning:
  - allow  -- run without asking
  - ask    -- escalate to normal permission prompt
  - deny   -- block execution",
    after_help = "\
QUICK START:
  1. may-i creates ~/.config/may-i/config.lisp on first run
  2. Edit rules to define your policy
  3. Run `may-i check` to validate
  4. Use `may-i eval 'cmd'` to test rules

Run `may-i reference` for full DSL syntax documentation."
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
        command: Option<String>,
    },
    /// Validate config and run all embedded checks
    Check {
        /// Show passing checks (not just failures)
        #[arg(short, long)]
        verbose: bool,
    },
    /// Parse a shell command and print the AST
    Parse {
        #[arg(required_unless_present = "file")]
        command: Option<String>,
        /// Read command from a file (use `-` for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Migrate v1 config to canonical syntax
    Migrate {
        /// Output file (defaults to stdout, use same as input for in-place)
        #[arg(short, long)]
        output: Option<String>,
        /// Skip confirmation prompt (non-TTY requires this flag)
        #[arg(long)]
        yes: bool,
        /// Show planned rewrites without modifying any file. Walks the
        /// `(load …)` graph and reports per-file diffs.
        #[arg(long)]
        dry_run: bool,
    },
    /// View or approve trust for loaded config programs
    Trust {
        /// Approve a specific program
        program: Option<String>,
        /// Approve all pending programs
        #[arg(long)]
        all: bool,
    },
    /// Show detailed DSL syntax reference
    Reference,
}

fn main() {
    miette::set_hook(Box::new(|_| {
        Box::new(miette::MietteHandlerOpts::new().build())
    }))
    .ok();

    if let Err(e) = run() {
        if e.downcast_ref::<may_i::cmd_check::CheckFailure>().is_some() {
            std::process::exit(1);
        }
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
            let piped_stdin = if !std::io::stdin().is_terminal() {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin()
                    .take(65536)
                    .read_to_string(&mut buf)
                    .map_err(|e| miette::miette!("failed to read stdin: {e}"))?;
                let trimmed = buf.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            } else {
                None
            };
            let resolved = resolve_eval_command(command, piped_stdin)?;
            may_i::cmd_eval::cmd_eval(&resolved, &facts, cli.json, cli.config.as_deref())?
        }
        Some(Command::Check { verbose }) => {
            may_i::cmd_check::cmd_check(cli.json, verbose, cli.config.as_deref())?
        }
        Some(Command::Parse { command, file }) => cmd_parse::cmd_parse(command, file, cli.json)?,
        Some(Command::Migrate {
            output,
            yes,
            dry_run,
        }) => cmd_migrate::cmd_migrate(cli.config.as_deref(), output.as_deref(), yes, dry_run)?,
        Some(Command::Trust { program, all }) => {
            may_i::cmd_trust::cmd_trust(program.as_deref(), all, cli.json, cli.config.as_deref())?
        }
        Some(Command::Reference) => cmd_help::cmd_help()?,
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

/// Resolve the eval command from either argv or stdin.
///
/// `argv` is the positional argument if provided. `piped_stdin` is `Some(content)`
/// when stdin is not a terminal, `None` when it is. Exactly one source must
/// provide a non-empty command.
fn resolve_eval_command(
    argv: Option<String>,
    piped_stdin: Option<String>,
) -> miette::Result<String> {
    match (argv, piped_stdin) {
        (Some(_), Some(_)) => Err(miette::miette!(
            "ambiguous input: command provided both as argument and on stdin"
        )),
        (Some(cmd), None) => Ok(cmd),
        (None, Some(content)) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                Err(miette::miette!("no command provided (stdin was empty)"))
            } else {
                Ok(trimmed.to_string())
            }
        }
        (None, None) => Err(miette::miette!(
            "no command provided\n\nUsage: may-i eval <COMMAND>\n       echo 'command' | may-i eval"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_argv_only() {
        let result = resolve_eval_command(Some("ls -la".into()), None).unwrap();
        assert_eq!(result, "ls -la");
    }

    #[test]
    fn resolve_stdin_only() {
        let result = resolve_eval_command(None, Some("rm -rf /\n".into())).unwrap();
        assert_eq!(result, "rm -rf /");
    }

    #[test]
    fn resolve_both_is_ambiguous() {
        let result = resolve_eval_command(Some("ls".into()), Some("rm\n".into()));
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ambiguous"),
            "expected ambiguous error, got: {err}"
        );
    }

    #[test]
    fn resolve_neither_is_error() {
        let result = resolve_eval_command(None, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_empty_stdin_is_error() {
        let result = resolve_eval_command(None, Some("   \n".into()));
        assert!(result.is_err());
    }
}

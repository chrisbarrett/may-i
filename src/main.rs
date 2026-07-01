// CLI interface — clap derive with TTY detection

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use may_i_shell_parser::Dialect;

mod cmd_fmt;
mod cmd_help;
mod cmd_hook;
mod cmd_parse;

use may_i::cmd_migrate;

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

    /// Path to config file. Resolver precedence, highest to lowest:
    /// `--config`, then `$MAYI_CONFIG`, then
    /// `$XDG_CONFIG_HOME/may-i/config.lisp`, then
    /// `~/.config/may-i/config.lisp`. After the primary config loads,
    /// repo-local files are also discovered at the git/hg/jj root
    /// (`.may-i.lisp`, `.may-i/*.lisp`, `.may-i.local.lisp`,
    /// `.claude/may-i.lisp`, `.claude/may-i.local.lisp`) and merged as
    /// Loaded rules — gated by `may-i trust` like any other loaded source.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<std::path::PathBuf>,

    /// Audit log threshold: off, deny, ask, or all. Overrides the
    /// `(audit (threshold …))` form and `MAYI_AUDIT_THRESHOLD`.
    #[arg(long, global = true, value_name = "THRESHOLD")]
    audit_threshold: Option<String>,

    /// Audit log file path. Overrides the `(audit (file …))` form and
    /// `MAYI_AUDIT_FILE`.
    #[arg(long, global = true, value_name = "FILE")]
    audit_file: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Collect audit overrides from the CLI flags and `MAYI_AUDIT_*` environment
/// variables. The env tier exists because hook mode is stdin-driven and
/// cannot take flags.
fn audit_overrides(cli: &Cli) -> may_i::audit::AuditOverrides {
    fn non_empty(var: &str) -> Option<String> {
        std::env::var(var).ok().filter(|s| !s.is_empty())
    }
    may_i::audit::AuditOverrides {
        flag_threshold: cli.audit_threshold.clone(),
        flag_file: cli.audit_file.clone(),
        env_threshold: non_empty("MAYI_AUDIT_THRESHOLD"),
        env_file: non_empty("MAYI_AUDIT_FILE"),
    }
}

/// Resolve the effective audit config from the loaded form plus overrides and
/// install it on the pipeline. An invalid flag/env threshold is a hard error.
fn apply_audit_config(
    pipeline: &mut may_i::pipeline::CommandPipeline,
    overrides: &may_i::audit::AuditOverrides,
) -> miette::Result<()> {
    let effective = may_i::audit::resolve_audit_config(&pipeline.config().audit, overrides)
        .map_err(|e| miette::miette!("{}", may_i_core::SafeText::new(e.to_string())))?;
    pipeline.set_audit(effective);
    Ok(())
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a shell command against the loaded config
    Eval {
        /// Add a runtime fact as :key or :key=value
        #[arg(long = "fact", value_name = "FACT")]
        facts: Vec<String>,
        /// Add NAME to a hypothetical entry environment (repeatable). The
        /// entry environment is the names-only snapshot of the exported
        /// environment the write-floor consults; it defaults to empty.
        #[arg(long = "env", value_name = "NAME")]
        env: Vec<String>,
        /// Capture this process's exported environment names into the entry
        /// environment, for reproducing a live hook decision. Combines with
        /// `--env`.
        #[arg(long = "inherit-env")]
        inherit_env: bool,
        /// Force the shell dialect (`bash` or `zsh`), overriding the dialect
        /// derived from `$SHELL`. Reproduces a decision under a chosen
        /// dialect independent of the ambient shell.
        #[arg(long = "dialect", value_name = "DIALECT")]
        dialect: Option<String>,
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
    /// Format config files in canonical form
    Fmt {
        /// Files to format (use `-` for stdin). Defaults to walking the
        /// `(load …)` graph from the primary config when omitted.
        files: Vec<String>,
        /// Check if files are formatted; exit 0 (clean), 1 (would change), 2 (error)
        #[arg(long)]
        check: bool,
    },
}

/// Map an executing shell path to a dialect by its basename: a path whose
/// final component is `zsh` (`zsh`, `/usr/bin/zsh`, `/opt/homebrew/bin/zsh`)
/// selects [`Dialect::Zsh`]; every other basename (`bash`, `sh`, `fish`, …)
/// falls back to [`Dialect::Bash`].
fn dialect_from_shell_path(path: &str) -> Dialect {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if basename == "zsh" {
        Dialect::Zsh
    } else {
        Dialect::Bash
    }
}

/// Resolve the invocation dialect. An explicit override (the `eval --dialect`
/// flag) always wins; otherwise the dialect is derived from the executing
/// shell's `$SHELL` basename, defaulting to [`Dialect::Bash`] when `$SHELL`
/// is absent or empty.
fn resolve_dialect(explicit: Option<Dialect>, shell_env: Option<&str>) -> Dialect {
    if let Some(dialect) = explicit {
        return dialect;
    }
    match shell_env {
        Some(shell) if !shell.is_empty() => dialect_from_shell_path(shell),
        _ => Dialect::Bash,
    }
}

/// Parse the `eval --dialect` flag value into a [`Dialect`].
fn parse_dialect_flag(value: &str) -> miette::Result<Dialect> {
    match value {
        "bash" => Ok(Dialect::Bash),
        "zsh" => Ok(Dialect::Zsh),
        other => Err(miette::miette!(
            "invalid --dialect {:?}: expected `bash` or `zsh`",
            may_i_core::SafeText::new(other.to_string())
        )),
    }
}

/// The executing shell reported by the environment (`$SHELL`), if any.
fn shell_env() -> Option<String> {
    std::env::var("SHELL").ok().filter(|s| !s.is_empty())
}

fn main() -> ExitCode {
    miette::set_hook(Box::new(|_| {
        Box::new(miette::MietteHandlerOpts::new().build())
    }))
    .ok();

    match run() {
        Ok(code) => code,
        Err(e) => {
            if e.downcast_ref::<may_i::cmd_check::CheckFailure>().is_some() {
                return ExitCode::from(1);
            }
            may_i::sink::report(&e);
            // Exit code 2 signals a blocking error to Claude Code hooks.
            // stderr is fed back to Claude so it can adjust its plan.
            ExitCode::from(2)
        }
    }
}

/// Main entry point for the CLI.
fn run() -> miette::Result<ExitCode> {
    let cli = Cli::parse();
    let audit_ov = audit_overrides(&cli);

    match cli.command {
        Some(Command::Eval {
            command,
            facts,
            env,
            inherit_env,
            dialect,
        }) => {
            let explicit_dialect = dialect.as_deref().map(parse_dialect_flag).transpose()?;
            let dialect = resolve_dialect(explicit_dialect, shell_env().as_deref());
            let piped_stdin = if !std::io::stdin().is_terminal() {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin()
                    .take(65536)
                    .read_to_string(&mut buf)
                    .map_err(|e| {
                        miette::miette!(
                            "failed to read stdin: {}",
                            may_i_core::SafeText::new(e.to_string())
                        )
                    })?;
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
            let mut pipeline =
                may_i::pipeline::CommandPipeline::load(cli.config.as_deref(), cli.json)?;
            apply_audit_config(&mut pipeline, &audit_ov)?;
            may_i::cmd_eval::cmd_eval(&mut pipeline, &resolved, &facts, &env, inherit_env, dialect)?
        }
        Some(Command::Check { verbose }) => {
            let mut pipeline =
                may_i::pipeline::CommandPipeline::load(cli.config.as_deref(), cli.json)?;
            may_i::cmd_check::cmd_check(&mut pipeline, verbose)?
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
        Some(Command::Fmt { files, check }) => {
            return cmd_fmt::cmd_fmt(cli.config.as_deref(), files, check);
        }
        None => {
            if std::io::stdin().is_terminal() {
                Cli::command().print_help().map_err(|e| {
                    miette::miette!(
                        "Failed to print help: {}",
                        may_i_core::SafeText::new(e.to_string())
                    )
                })?;
                may_i::sink::with_stdout(|w| {
                    let _ = writeln!(w);
                });
            } else {
                let mut pipeline =
                    may_i::pipeline::CommandPipeline::load(cli.config.as_deref(), cli.json)?;
                apply_audit_config(&mut pipeline, &audit_ov)?;
                // Hook mode derives the dialect from the executing shell; there
                // is no override flag on the stdin-driven path.
                let dialect = resolve_dialect(None, shell_env().as_deref());
                cmd_hook::cmd_hook(&mut pipeline, dialect)?;
            }
        }
    }

    Ok(ExitCode::SUCCESS)
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

    // ── Dialect resolution ──────────────────────────────────────────

    #[test]
    fn shell_path_basename_maps_to_dialect() {
        assert_eq!(dialect_from_shell_path("zsh"), Dialect::Zsh);
        assert_eq!(dialect_from_shell_path("/usr/bin/zsh"), Dialect::Zsh);
        assert_eq!(
            dialect_from_shell_path("/opt/homebrew/bin/zsh"),
            Dialect::Zsh
        );
        assert_eq!(dialect_from_shell_path("bash"), Dialect::Bash);
        assert_eq!(dialect_from_shell_path("/bin/bash"), Dialect::Bash);
        assert_eq!(dialect_from_shell_path("/usr/bin/fish"), Dialect::Bash);
        assert_eq!(dialect_from_shell_path("/bin/sh"), Dialect::Bash);
        // A path whose basename merely contains `zsh` is not `zsh`.
        assert_eq!(dialect_from_shell_path("/bin/myzsh"), Dialect::Bash);
        assert_eq!(dialect_from_shell_path(""), Dialect::Bash);
    }

    #[test]
    fn resolve_dialect_uses_shell_when_no_override() {
        assert_eq!(resolve_dialect(None, Some("/usr/bin/zsh")), Dialect::Zsh);
        assert_eq!(resolve_dialect(None, Some("/bin/bash")), Dialect::Bash);
    }

    #[test]
    fn resolve_dialect_defaults_bash_when_shell_absent_or_empty() {
        assert_eq!(resolve_dialect(None, None), Dialect::Bash);
        assert_eq!(resolve_dialect(None, Some("")), Dialect::Bash);
    }

    #[test]
    fn resolve_dialect_override_wins_over_shell() {
        // Explicit override beats the `$SHELL`-derived value in both directions.
        assert_eq!(
            resolve_dialect(Some(Dialect::Bash), Some("/usr/bin/zsh")),
            Dialect::Bash
        );
        assert_eq!(
            resolve_dialect(Some(Dialect::Zsh), Some("/bin/bash")),
            Dialect::Zsh
        );
    }

    #[test]
    fn parse_dialect_flag_accepts_known_values() {
        assert_eq!(parse_dialect_flag("bash").unwrap(), Dialect::Bash);
        assert_eq!(parse_dialect_flag("zsh").unwrap(), Dialect::Zsh);
        assert!(parse_dialect_flag("fish").is_err());
        assert!(parse_dialect_flag("").is_err());
    }
}

# CLI Interface

Clap-based CLI with TTY-aware default behavior. When invoked with no subcommand
in a TTY, print help. When stdin is not a TTY (i.e. piped from Claude Code),
read the hook payload from stdin.

---

## R1: Top-level CLI structure (clap derive)

Migrate from manual arg dispatch to clap's derive API.

```rust
#[derive(Parser)]
#[command(name = "may-i", version, about = "Shell command authorization evaluator")]
struct Cli {
    /// Output format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Eval { command: String },
    Check,
    Parse {
        command: Option<String>,
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}
```

**Verify:** `cargo build`; `may-i --help`; `may-i --version` prints `may-i
0.1.0`

## R2: No-subcommand behavior (TTY detection)

Use `std::io::IsTerminal` (stable, no extra deps) to detect whether stdin is a
terminal.

| Condition                       | Behavior                    |
| :------------------------------ | :-------------------------- |
| No subcommand + stdin is a TTY  | Print clap help, exit 0     |
| No subcommand + stdin is a pipe | Run hook mode (read stdin)  |

Implementation: when `Cli.command` is `None`, check
`std::io::stdin().is_terminal()`. If true, print help via
`Cli::command().print_help()` and return. Otherwise, enter hook mode.

**Verify:** `may-i` in a terminal prints help; `echo '{}' | may-i` enters hook
mode

## R3: Global `--json` flag

A `--json` flag on the top-level `Cli` struct, marked `global = true`, controls
output format for all subcommands that produce structured output.

| Subcommand | `--json` effect                                           |
| :--------- | :-------------------------------------------------------- |
| `eval`     | `{"decision":"allow","reason":"..."}` (existing behavior) |
| `check`    | `{"passed":N,"failed":N,"results":[...]}`                 |
| Hook mode  | Always JSON (Claude Code protocol); flag is ignored       |
| `parse`    | No effect (always debug AST)                              |

**Verify:** `may-i --json eval 'ls'`; `may-i --json check`

## R4: Subcommands

### eval

```
may-i eval '<command>'
may-i --json eval '<command>'
```

Evaluate a shell command against the loaded config. Print human-readable or JSON
result depending on `--json`.

### check

```
may-i check
may-i --json check
```

Load config, validate, run all embedded examples. Report pass/fail per example.
With `--json`, output structured results.

### parse

```
may-i parse '<command>'
may-i parse -f <file>
may-i parse -f -
```

Parse a shell command and print the AST. Always uses Rust `{:#?}` debug format.

## R5: Exit codes

| Scenario                | Code |
| :---------------------- | :--- |
| Success / help printed  | 0    |
| Config or runtime error | 1    |
| Example failure (check) | 1    |

No change from existing behavior.

**Verify:** integration tests assert exit codes

## Constraints

- No additional dependencies — `clap` (already present) and `std::io::IsTerminal`
- `--version` shows `may-i <version>` from `Cargo.toml` (clap default)
- Hook mode JSON output format is unchanged (Claude Code protocol compatibility)

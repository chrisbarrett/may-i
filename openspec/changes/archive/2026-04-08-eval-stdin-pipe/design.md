## Context

The `eval` subcommand currently requires a positional `command: String` argument. The `Parse` subcommand already supports reading from stdin via `-f -`, but `eval` has no such mechanism. The codebase already uses `std::io::IsTerminal` in `main.rs` for the hook-mode TTY detection pattern.

## Goals / Non-Goals

**Goals:**
- Allow `echo 'cmd' | may-i eval` to read the command from stdin.
- Error clearly when both stdin and argv provide a command.
- Error clearly when neither provides a command (TTY, no arg).

**Non-Goals:**
- Adding a `-f`/`--file` flag to eval (keep it simple; auto-detect is sufficient).
- Streaming or multi-command stdin processing.

## Decisions

### 1. Resolve command source in `main.rs`, not `cmd_eval`

The TTY check and stdin reading happen in the `run()` match arm for `Eval`. `cmd_eval` continues to receive a `&str` command. This keeps `cmd_eval` pure and testable without mocking stdin.

**Alternative**: Move detection into `cmd_eval`. Rejected because it couples business logic to I/O detection.

### 2. Use `is_terminal()` on stdin to detect pipe

`std::io::stdin().is_terminal()` (already imported) distinguishes TTY from pipe/redirect. When stdin is not a terminal, read it. This is the standard Unix idiom.

### 3. Trim the stdin input

`echo 'ls'` sends `ls\n`. Trim whitespace from stdin input before passing to eval. This matches user expectations.

### 4. Limit stdin read size

Follow the existing pattern in `cmd_claude_code_hook.rs`: use `.take(65536)` to cap stdin reads. Shell commands shouldn't be 64KB.

## Risks / Trade-offs

- **stdin from `/dev/null`**: Produces empty string after trim → caught by "neither source provided" error. No special handling needed.
- **Multi-line input**: Entire stdin becomes one command string, same as if passed via argv with embedded newlines. The parser already handles this.

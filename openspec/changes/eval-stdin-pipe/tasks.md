## 1. CLI Argument Change

- [x] 1.1 Change `Eval` variant's `command` field from `String` to `Option<String>` in `main.rs`

## 2. Command Resolution

- [x] 2.1 Add a `resolve_eval_command` function in `main.rs` that takes `Option<String>` (argv) and checks `stdin.is_terminal()` to determine the command source, returning `Result<String>` with clear errors for ambiguous, missing, and empty-stdin cases
- [x] 2.2 Wire `resolve_eval_command` into the `Eval` match arm in `run()`, passing the resolved command to `cmd_eval`

## 3. Tests

- [x] 3.1 Write unit tests for `resolve_eval_command` covering: argv-only, stdin-only, both (error), neither (error), empty stdin (error)
- [x] 3.2 Add integration test: pipe a command via stdin to `may-i eval` and verify correct evaluation

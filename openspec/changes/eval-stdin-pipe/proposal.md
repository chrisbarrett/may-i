## Why

The `eval` subcommand only accepts the shell command as a positional argument. This makes it awkward to use in pipelines (e.g., `echo 'rm -rf /' | may-i eval`). Reading from stdin when piped would make `eval` composable with other tools, matching Unix conventions.

## What Changes

- Make the `command` positional argument optional on the `Eval` variant.
- When stdin is not a TTY (i.e., piped), read the command from stdin instead.
- If both a positional argument and piped stdin are present, error with a clear message about the ambiguity.
- If neither is present (TTY, no argument), error with a usage hint.

## Capabilities

### New Capabilities
- `eval-stdin`: Reading the eval command from stdin when piped, with ambiguity detection.

### Modified Capabilities

(none)

## Impact

- `src/main.rs`: `Eval` variant's `command` field becomes `Option<String>`.
- `src/cmd_eval.rs`: `cmd_eval` receives the resolved command string (no change to its signature needed if resolution happens in `main.rs`).
- No dependency changes.

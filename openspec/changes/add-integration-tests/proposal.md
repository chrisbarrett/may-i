## Why

Several user-facing subcommands have zero end-to-end test coverage. The `check`, `parse`, `migrate` (as subprocess), and `eval --fact` commands are untested at the integration level, as is the error path for missing config files and `--json` hook output mode.

## What Changes

- Add integration tests for `may-i check` subcommand (valid config, failing checks, verbose mode)
- Add integration tests for `may-i parse` subcommand (valid command, with file flag)
- Add integration tests for `may-i migrate` as a subprocess (v1 config in, migrated output)
- Add integration test for `may-i eval` with `--fact` flags
- Add integration test for missing/nonexistent config file error path
- Add integration test for hook with `--json` output mode
- Use shared helpers from `tests/common/mod.rs` (from test-suite-cleanup change)

## Capabilities

### New Capabilities

- `integration-test-coverage`: End-to-end tests for all CLI subcommands

### Modified Capabilities

## Impact

- `tests/` — new integration test files
- Depends on test-suite-cleanup change for shared helpers

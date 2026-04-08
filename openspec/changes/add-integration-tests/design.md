## Context

The `check`, `parse`, `migrate` subcommands and several `eval` modes have no end-to-end integration tests. These are user-facing commands.

## Goals / Non-Goals

**Goals:**
- Cover all CLI subcommands with at least one happy-path and one error-path integration test
- Test JSON output modes where applicable

**Non-Goals:**
- Exhaustive coverage of every flag combination
- Replacing existing unit tests with integration tests

## Decisions

### One test file per subcommand group
- `tests/check_integration.rs` — check subcommand
- `tests/parse_integration.rs` — parse subcommand
- `tests/migrate_integration.rs` — migrate as subprocess
- Add eval --fact tests to existing `tests/eval_stdin.rs`
- Add --json and error tests to existing `tests/hook_integration.rs`

### Use shared helpers from tests/common/
Depends on test-suite-cleanup change. Import `write_config`, `may_i` builder, etc.

### Test configs should use v2 syntax
All new test fixtures use v2 (canonical) syntax directly — these tests are testing CLI behavior, not migration.

## Risks / Trade-offs

- [Integration tests are slower than unit tests] → Acceptable for CLI coverage. Keep test configs minimal.
- [Depends on test-suite-cleanup for shared helpers] → Can proceed independently with duplicated helpers, then deduplicate.

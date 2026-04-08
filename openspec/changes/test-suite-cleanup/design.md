## Context

Integration test files duplicate helper functions. One test uses v1 syntax unnecessarily. Several tests in migration_diff.rs test nothing meaningful. Unsafe env var manipulation in io.rs tests risks thread-safety issues.

## Goals / Non-Goals

**Goals:**
- Eliminate duplicated test boilerplate
- Remove meaningless tests
- Fix thread-safety risk in config path tests

**Non-Goals:**
- Adding new test coverage (separate changes handle that)
- Changing test frameworks

## Decisions

### Extract tests/common/mod.rs
Standard Rust pattern for sharing integration test helpers. Move `write_config`, `bash_payload`, and `may_i` command builder there. Integration test files import via `mod common;`.

### Use temp_env crate for env var tests
Replace manual `unsafe { env::set_var(...) }` / `env::remove_var(...)` with `temp_env::with_vars` which handles save/restore automatically and is safe. Add `temp_env` as a dev-dependency of the config crate.

### Keep migration_diff.rs trivia and analysis tests
Only remove the four tests that are pure struct construction (lines 120-173). Keep the `analyze_migration`-based tests that exercise real migration logic.

## Risks / Trade-offs

- [tests/common/mod.rs creates a test binary for common/] → Mitigate by ensuring common/mod.rs has no #[test] functions, only helpers. Cargo won't create a binary for it.

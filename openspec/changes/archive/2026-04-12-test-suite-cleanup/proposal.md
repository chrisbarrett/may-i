## Why

Integration tests have duplicated helpers, use deprecated v1 syntax unnecessarily, and contain tests that don't test meaningful behavior. Cleaning these up reduces maintenance burden and makes the test suite more trustworthy.

## What Changes

- Extract shared test helpers (`write_config`, `bash_payload`, `may_i` command builder) into `tests/common/mod.rs`
- Update `tests/hook_integration.rs:69` to use v2 syntax directly (tests argument quoting, not migration)
- Remove struct-construction "tests" from `tests/migration_diff.rs` that test nothing meaningful (lines 120-173)
- Remove `test_terminal_width_detection` — tests a third-party crate
- Replace unsafe `env::set_var`/`env::remove_var` in `crates/config/src/io.rs:251-322` with `temp_env` or `#[serial]`
- Scope `#![allow(clippy::vec_box)]` in `crates/sexpr/src/cst.rs` to specific items instead of module-level
- Verify `#![allow(unused_assignments)]` in `crates/config/src/errors.rs` is still needed with current miette

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `tests/` — helper extraction, test removal, syntax update
- `crates/config/src/io.rs` — test safety improvement
- `crates/sexpr/src/cst.rs` — clippy scope tightening
- `crates/config/src/errors.rs` — lint verification

## Why

The root binary carries unused dependencies that increase compile time and binary size. The test archive directory contains 1,310 lines of dead code that will never compile.

## What Changes

- Remove `minus = "5.3.1"` from root Cargo.toml — completely unused
- Remove `serde` from root Cargo.toml — unused; shell-parser carries its own dependency
- Move `terminal_size` to `[dev-dependencies]` — only used in tests/migration_diff.rs
- Check if `colored` is needed in root Cargo.toml or satisfied transitively via pp/layout
- Delete `tests/archive/` directory (eval_e2e.rs, hook_e2e.rs, config_error_snapshots.rs, wrapper_snapshots.rs) — never compiled by Cargo, uses deprecated `--v2` flag
- Remove dead re-export `DEFAULT_RECURSION_LIMIT` from `crates/engine/src/eval/mod.rs`
- Run `cargo clippy --fix --workspace --all-targets` to clear ~15 auto-fixable warnings

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `Cargo.toml` — dependency removals
- `tests/archive/` — deletion
- `crates/engine/src/eval/mod.rs` — dead re-export removal
- Various files — clippy auto-fixes

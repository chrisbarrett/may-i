## 1. Core Crate - Flatten v2 Module

- [x] 1.1 Move `crates/core/src/v2/ast.rs` to `crates/core/src/ast.rs`
- [x] 1.2 Move `crates/core/src/v2/pattern.rs` to `crates/core/src/pattern.rs`
- [x] 1.3 Update `crates/core/src/v2/mod.rs` to re-export from new locations
- [x] 1.4 Create `crates/core/src/legacy/mod.rs` for legacy types
- [x] 1.5 Update `crates/core/src/lib.rs` re-exports (remove V2 prefixes, add legacy module)
- [x] 1.6 Update imports within moved files (`use crate::v2::` → `use crate::`)
- [x] 1.7 Compile `crates/core` and fix any errors

## 2. Config Crate - Flatten v2 Module

- [x] 2.1 Move `crates/config/src/v2/config.rs` to `crates/config/src/config.rs`
- [x] 2.2 Move `crates/config/src/v2/effect.rs` to `crates/config/src/effect.rs`
- [x] 2.3 Move `crates/config/src/v2/rule.rs` to `crates/config/src/rule.rs`
- [x] 2.4 Move `crates/config/src/v2/pattern.rs` to `crates/config/src/pattern.rs`
- [x] 2.5 Move `crates/config/src/v2/predicate.rs` to `crates/config/src/predicate.rs`
- [x] 2.6 Move `crates/config/src/v2/command.rs` to `crates/config/src/command.rs`
- [x] 2.7 Move `crates/config/src/v2/resolve.rs` to `crates/config/src/resolve.rs`
- [x] 2.8 Move `crates/config/src/v2/migrate.rs` to `crates/config/src/migrate.rs`
- [x] 2.9 Move `crates/config/src/v2/migration_tests.rs` to `crates/config/src/migration_tests.rs`
- [x] 2.10 Update `crates/config/src/v2/mod.rs` to re-export
- [x] 2.11 Update `crates/config/src/lib.rs` re-exports
- [x] 2.12 Rename `load_v2()` to `load()` in `crates/config/src/io.rs`
- [x] 2.13 Update all imports in moved files
- [x] 2.14 Compile `crates/config` and fix any errors

## 3. Engine Crate - Flatten v2 Module

- [x] 3.1 Move `crates/engine/src/v2/eval.rs` to `crates/engine/src/eval.rs`
- [x] 3.2 Move `crates/engine/src/v2/trace.rs` to `crates/engine/src/trace.rs`
- [x] 3.3 Move `crates/engine/src/v2/integration_tests.rs` to `crates/engine/src/integration_tests.rs`
- [x] 3.4 Update `crates/engine/src/v2/mod.rs` to re-export
- [x] 3.5 Update `crates/engine/src/lib.rs` re-exports
- [x] 3.6 Rename `evaluate_v2()` to `evaluate()` in moved eval.rs
- [x] 3.7 Update all imports in moved files
- [x] 3.8 Compile `crates/engine` and fix any errors

## 4. CLI Commands - Update Imports

- [x] 4.1 Update `src/cmd_check.rs` imports
- [x] 4.2 Update `src/cmd_eval.rs` imports and v2 function calls
- [x] 4.3 Update `src/cmd_claude_code_hook.rs` imports and references
- [x] 4.4 Update other `src/cmd_*.rs` files with v2 references
- [x] 4.5 Compile src/ directory

## 5. Tests - Update All References

- [x] 5.1 Update test imports for canonical types
- [x] 5.2 Update test files calling `load()` or `evaluate()` with new signatures
- [x] 5.3 Run `cargo test` and fix failures

## 6. Documentation - Remove v2 References

- [x] 6.1 Search for "v2 syntax" in comments and docstrings
- [x] 6.2 Update README.md references
- [x] 6.3 Review all changed files for stale v2 comments

## 7. Cleanup and Verification

- [x] 7.1 Delete empty `crates/core/src/v2/` directory
- [x] 7.2 Delete empty `crates/config/src/v2/` directory
- [x] 7.3 Delete empty `crates/engine/src/v2/` directory
- [x] 7.4 Run `cargo fmt` on all changed files
- [x] 7.5 Run `cargo clippy` and fix warnings
- [x] 7.6 Run full test suite `cargo test --workspace`
- [x] 7.7 Verify `cargo build` succeeds for entire workspace
- [x] 7.8 Check for remaining "v2" references

## Implementation Status

**Completed:**
- All core crate files moved and imports updated
- All config crate files moved and imports updated
- All engine crate files moved and imports updated
- CLI commands updated to use legacy types where needed
- All test files updated with proper imports
- All documentation updated to remove "v2" references
- All v2 directories deleted
- Workspace builds and tests pass

**All tasks complete!**

## Key Changes Made

1. **Core Crate**: Moved `ast.rs` and `pattern.rs` from `v2/` to root, created `legacy/` module for v1 types
2. **Config Crate**: Moved all parser files from `v2/` to root, renamed `load_v2()` to `load()`
3. **Engine Crate**: Moved `eval.rs` and `trace.rs` from `v2/` to root, renamed `evaluate_v2()` to `evaluate()`
4. **CLI**: Updated to use `may_i_core::legacy::*` types for backward compatibility
5. **Type Structure**:
   - Canonical types: `may_i_core::{Config, Effect, Rule, ...}` (from v2)
   - Legacy types: `may_i_core::legacy::{Config, Effect, Rule, ...}` (v1 types)

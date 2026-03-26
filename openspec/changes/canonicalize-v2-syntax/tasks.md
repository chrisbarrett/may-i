## 1. Core Crate - Flatten v2 Module

- [ ] 1.1 Move `crates/core/src/v2/ast.rs` to `crates/core/src/ast.rs`
- [ ] 1.2 Move `crates/core/src/v2/pattern.rs` to `crates/core/src/pattern.rs`
- [ ] 1.3 Update `crates/core/src/v2/mod.rs` to re-export from new locations or delete if empty
- [ ] 1.4 Create `crates/core/src/legacy/mod.rs` and move legacy types from `types.rs`
- [ ] 1.5 Update `crates/core/src/lib.rs` re-exports (remove V2 prefixes, add legacy module)
- [ ] 1.6 Update imports within moved files (`use crate::v2::` → `use crate::`)
- [ ] 1.7 Compile `crates/core` and fix any errors

## 2. Config Crate - Flatten v2 Module

- [ ] 2.1 Move `crates/config/src/v2/config.rs` to `crates/config/src/config.rs`
- [ ] 2.2 Move `crates/config/src/v2/effect.rs` to `crates/config/src/effect.rs`
- [ ] 2.3 Move `crates/config/src/v2/rule.rs` to `crates/config/src/rule.rs`
- [ ] 2.4 Move `crates/config/src/v2/pattern.rs` to `crates/config/src/pattern.rs`
- [ ] 2.5 Move `crates/config/src/v2/predicate.rs` to `crates/config/src/predicate.rs`
- [ ] 2.6 Move `crates/config/src/v2/command.rs` to `crates/config/src/command.rs`
- [ ] 2.7 Move `crates/config/src/v2/resolve.rs` to `crates/config/src/resolve.rs`
- [ ] 2.8 Move `crates/config/src/v2/migrate.rs` to `crates/config/src/migrate.rs`
- [ ] 2.9 Move `crates/config/src/v2/migration_tests.rs` to `crates/config/src/migration_tests.rs`
- [ ] 2.10 Update `crates/config/src/v2/mod.rs` to re-export or delete
- [ ] 2.11 Update `crates/config/src/lib.rs` re-exports
- [ ] 2.12 Rename `load_v2()` to `load()` in `crates/config/src/io.rs`
- [ ] 2.13 Update all imports in moved files (`use crate::v2::` → `use crate::`, `may_i_core::v2::` → `may_i_core::`)
- [ ] 2.14 Compile `crates/config` and fix any errors

## 3. Engine Crate - Flatten v2 Module

- [ ] 3.1 Move `crates/engine/src/v2/eval.rs` to `crates/engine/src/eval.rs`
- [ ] 3.2 Move `crates/engine/src/v2/trace.rs` to `crates/engine/src/trace.rs`
- [ ] 3.3 Move `crates/engine/src/v2/integration_tests.rs` to `crates/engine/src/integration_tests.rs`
- [ ] 3.4 Update `crates/engine/src/v2/mod.rs` to re-export or delete
- [ ] 3.5 Update `crates/engine/src/lib.rs` re-exports
- [ ] 3.6 Rename `evaluate_v2()` to `evaluate()` in moved eval.rs
- [ ] 3.7 Update all imports in moved files (`use crate::v2::` → `use crate::`, `may_i_core::v2::` → `may_i_core::`)
- [ ] 3.8 Compile `crates/engine` and fix any errors

## 4. CLI Commands - Update Imports

- [ ] 4.1 Update `src/cmd_check.rs` imports (`may_i_core::Config` → `may_i_core::legacy::Config` or migrate to canonical)
- [ ] 4.2 Update `src/cmd_eval.rs` imports and v2 function calls
- [ ] 4.3 Update `src/cmd_migrate.rs` imports and references
- [ ] 4.4 Update any other `src/cmd_*.rs` files with v2 references
- [ ] 4.5 Update `src/main.rs` if it has v2 references
- [ ] 4.6 Compile src/ directory and fix errors

## 5. Tests - Update All References

- [ ] 5.1 Update `tests/migration_diff.rs` imports and assertions
- [ ] 5.2 Update any other test files with `v2` module references
- [ ] 5.3 Update test files using `may_i_core::V2*` types
- [ ] 5.4 Update test files calling `load_v2()` or `evaluate_v2()`
- [ ] 5.5 Run `cargo test` and fix failures

## 6. Documentation - Remove v2 References

- [ ] 6.1 Search for "v2 syntax" in comments and docstrings, update to canonical descriptions
- [ ] 6.2 Search for "v2 unified DSL" references and update
- [ ] 6.3 Update `src/cmd_help.rs` help text (remove --v2 flag references if appropriate)
- [ ] 6.4 Update any README.md references to v2
- [ ] 6.5 Review all changed files for stale v2 comments

## 7. Cleanup and Verification

- [ ] 7.1 Delete empty `crates/core/src/v2/` directory
- [ ] 7.2 Delete empty `crates/config/src/v2/` directory
- [ ] 7.3 Delete empty `crates/engine/src/v2/` directory
- [ ] 7.4 Run `cargo fmt` on all changed files
- [ ] 7.5 Run `cargo clippy` and fix warnings
- [ ] 7.6 Run full test suite `cargo test --workspace`
- [ ] 7.7 Verify `cargo build` succeeds for entire workspace
- [ ] 7.8 Check for any remaining "v2" references with `rg -i "v2" --type rust` (should only be in archive/ or historical comments)

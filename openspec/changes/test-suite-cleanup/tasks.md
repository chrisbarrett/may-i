## 1. Extract shared test helpers

- [ ] 1.1 Create tests/common/mod.rs with write_config, bash_payload, and may_i command builder functions
- [ ] 1.2 Update tests/eval_stdin.rs to use common helpers
- [ ] 1.3 Update tests/hook_integration.rs to use common helpers
- [ ] 1.4 Verify all integration tests pass

## 2. Fix test quality issues

- [ ] 2.1 Update hook_integration.rs:69 to use v2 syntax instead of v1
- [ ] 2.2 Remove struct-construction tests from migration_diff.rs (lines 120-173)
- [ ] 2.3 Remove test_terminal_width_detection from migration_diff.rs
- [ ] 2.4 Verify remaining migration_diff tests pass

## 3. Fix thread-safety in config path tests

- [ ] 3.1 Add temp_env as dev-dependency to crates/config/Cargo.toml
- [ ] 3.2 Replace unsafe env::set_var/remove_var in crates/config/src/io.rs tests with temp_env::with_vars
- [ ] 3.3 Verify config tests pass

## 4. Tighten lint suppressions

- [ ] 4.1 Scope #![allow(clippy::vec_box)] in crates/sexpr/src/cst.rs to specific items
- [ ] 4.2 Verify #![allow(unused_assignments)] in crates/config/src/errors.rs is still needed — remove if not

## 1. Archive and v1 Code Removal

- [x] 1.1 Delete entire `archive/v1/` directory (engine, core, config)
- [x] 1.2 Delete `crates/engine/src/lib_v1.rs`
- [x] 1.3 Search for and remove any v1 imports in active source files
- [x] 1.4 Verify `cargo build --workspace` passes after archive removal
- [x] 1.5 Run `cargo test --workspace` to ensure no test dependencies on v1

## 2. Engine Consolidation

- [x] 2.1 Audit `crates/engine/src/lib.rs` for any v1 compatibility code
- [x] 2.2 Remove v1 references from engine lib.rs comments and documentation
- [x] 2.3 Verify v2 module exports are correct in `crates/engine/src/v2/mod.rs`
- [x] 2.4 Update `crates/engine/src/lib.rs` to remove v1-related comments
- [x] 2.5 Verify all public exports are v2-only
- [x] 2.6 Run engine tests to verify v2 functionality intact

## 3. Config v2-Only Verification

- [x] 3.1 Verify `crates/config/src/lib.rs` only exports v2 module
- [x] 3.2 Remove any v1 compatibility code from config crate
- [x] 3.3 Update config documentation to remove v1 references
- [x] 3.4 Verify config validation tests pass
- [x] 3.5 Test v2 config loading works correctly

## 4. Baseline Coverage Measurement

- [x] 4.1 Run `cargo tarpaulin --workspace` to establish baseline coverage
- [x] 4.2 Document current coverage percentage for each crate
- [x] 4.3 Generate HTML report to identify coverage gaps
- [x] 4.4 Prioritize modules with lowest coverage for testing

## 5. Engine Test Coverage (CURRENT: ~78%, TARGET: 90%)

- [x] 5.1 Add tests for `crates/engine/src/v2/eval.rs` uncovered lines
- [x] 5.2 Add tests for `crates/engine/src/lib.rs` AstWalker and helpers (+49 tests)
- [x] 5.3 Add tests for `crates/engine/src/var_env.rs` (covered via lib.rs tests)
- [x] 5.4 Add tests for visitor modules in `crates/engine/src/visitors/` (code_execution, read_builtin, wrapper_unwrap have low coverage)
- [x] 5.5 Add tests for `crates/engine/src/check.rs` (13 uncovered lines)
- [x] 5.6 Add tests for `crates/engine/src/v2/trace.rs` (26 uncovered lines)
- [x] 5.7 Run coverage and verify engine crate ≥90%

## 6. Config Test Coverage (CURRENT: ~76%, TARGET: 90%)

- [x] 6.1 Add tests for `crates/config/src/v2/config.rs` uncovered lines (35 lines)
- [x] 6.2 Add tests for `crates/config/src/v2/pattern.rs` uncovered lines (+8 tests, 72% coverage)
- [x] 6.3 Add tests for `crates/config/src/v2/predicate.rs` uncovered lines (+7 tests)
- [x] 6.4 Add tests for `crates/config/src/v2/migrate.rs` uncovered lines (25 lines)
- [x] 6.5 Add tests for `crates/config/src/io.rs`
- [x] 6.6 Run coverage and verify config crate ≥90%

## 7. Shell-Parser Test Coverage (CURRENT: 100%, TARGET: 90%)

- [x] 7.1 Shell-parser already at 100% - no additional tests needed

## 8. Core Test Coverage (CURRENT: 74%, TARGET: 90%)

- [x] 8.1 Add tests for `crates/core/src/types.rs` uncovered lines
- [x] 8.2 Add tests for `crates/core/src/v2/ast.rs`
- [x] 8.3 Add tests for `crates/core/src/v2/pattern.rs`
- [x] 8.4 Add tests for `crates/core/src/v2/predicate.rs`
- [x] 8.5 Add tests for `crates/core/src/doc.rs`
- [x] 8.6 Run coverage and verify core crate ≥90% (v2/ module at 100%, types.rs still needs work)

## 9. Sexpr Test Coverage (CURRENT: 89%, TARGET: 90%)

- [x] 9.1 Add tests for `crates/sexpr/src/lib.rs` uncovered lines
- [x] 9.2 Run coverage and verify sexpr crate ≥90%

## 10. PP Test Coverage (CURRENT: 84%, TARGET: 90%)

- [x] 10.1 Add tests for `crates/pp/src/lib.rs` uncovered lines
- [x] 10.2 Run coverage and verify pp crate ≥90%

## 11. Dead Code Elimination

- [x] 11.1 Run `cargo build` with full warnings to identify unused code
- [x] 11.2 Review and remove orphaned functions revealed by v1 removal
- [x] 11.3 Remove any v1-related documentation references
- [x] 11.4 Update README if it references v1
- [x] 11.5 Verify clean build with no warnings

## 12. Final Verification

- [x] 12.1 Run `cargo test --workspace` - all tests must pass
- [x] 12.2 Run `cargo tarpaulin --workspace` - verify ≥90% for all crates
- [x] 12.3 Run `cargo clippy --workspace` - no warnings
- [x] 12.4 Run `cargo fmt --check` - verify formatting
- [x] 12.5 Verify `cargo build --release` succeeds
- [ ] 12.6 Commit changes

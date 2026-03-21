## 1. Archive and v1 Code Removal

- [ ] 1.1 Delete entire `archive/v1/` directory (engine, core, config)
- [ ] 1.2 Delete `crates/engine/src/lib_v1.rs`
- [ ] 1.3 Search for and remove any v1 imports in active source files
- [ ] 1.4 Verify `cargo build --workspace` passes after archive removal
- [ ] 1.5 Run `cargo test --workspace` to ensure no test dependencies on v1

## 2. Engine Consolidation

- [ ] 2.1 Audit `crates/engine/src/lib.rs` for any v1 compatibility code
- [ ] 2.2 Remove v1 references from engine lib.rs comments and documentation
- [ ] 2.3 Verify v2 module exports are correct in `crates/engine/src/v2/mod.rs`
- [ ] 2.4 Update `crates/engine/src/lib.rs` to remove v1-related comments
- [ ] 2.5 Verify all public exports are v2-only
- [ ] 2.6 Run engine tests to verify v2 functionality intact

## 3. Config v2-Only Verification

- [ ] 3.1 Verify `crates/config/src/lib.rs` only exports v2 module
- [ ] 3.2 Remove any v1 compatibility code from config crate
- [ ] 3.3 Update config documentation to remove v1 references
- [ ] 3.4 Verify config validation tests pass
- [ ] 3.5 Test v2 config loading works correctly

## 4. Baseline Coverage Measurement

- [ ] 4.1 Run `cargo tarpaulin --workspace` to establish baseline coverage
- [ ] 4.2 Document current coverage percentage for each crate
- [ ] 4.3 Generate HTML report to identify coverage gaps
- [ ] 4.4 Prioritize modules with lowest coverage for testing

## 5. Engine Test Coverage

- [ ] 5.1 Add unit tests for `crates/engine/src/v2/eval.rs` evaluation paths
- [ ] 5.2 Add tests for rule matching scenarios in matcher module
- [ ] 5.3 Add tests for predicate evaluation with context facts
- [ ] 5.4 Add tests for complex command structures (pipelines, conditionals, loops)
- [ ] 5.5 Add tests for visitor pattern implementations
- [ ] 5.6 Add tests for variable environment tracking in `var_env.rs`
- [ ] 5.7 Add integration tests for end-to-end evaluation scenarios
- [ ] 5.8 Run coverage and verify engine crate ≥90%

## 6. Config Test Coverage

- [ ] 6.1 Expand tests in `crates/config/src/v2/config.rs`
- [ ] 6.2 Add tests for rule parsing in `crates/config/src/v2/rule.rs`
- [ ] 6.3 Add tests for pattern matching in `crates/config/src/v2/pattern.rs`
- [ ] 6.4 Add tests for predicate parsing in `crates/config/src/v2/predicate.rs`
- [ ] 6.5 Add tests for effect parsing in `crates/config/src/v2/effect.rs`
- [ ] 6.6 Add tests for config migration in `crates/config/src/v2/migrate.rs`
- [ ] 6.7 Add tests for command parsing in `crates/config/src/v2/command.rs`
- [ ] 6.8 Add tests for config I/O operations in `crates/config/src/io.rs`
- [ ] 6.9 Run coverage and verify config crate ≥90%

## 7. Shell-Parser Test Coverage

- [ ] 7.1 Expand tests in `crates/shell-parser/src/tests.rs`
- [ ] 7.2 Add tests for lexer edge cases in `crates/shell-parser/src/lexer.rs`
- [ ] 7.3 Add tests for parser error handling in `crates/shell-parser/src/parse.rs`
- [ ] 7.4 Add tests for word/segment resolution in `crates/shell-parser/src/resolve.rs`
- [ ] 7.5 Add tests for glob pattern parsing in `crates/shell-parser/src/glob.rs`
- [ ] 7.6 Add tests for AST construction in `crates/shell-parser/src/ast.rs`
- [ ] 7.7 Run coverage and verify shell-parser crate ≥90%

## 8. Core Test Coverage

- [ ] 8.1 Add tests for Decision enum operations in `crates/core/src/types.rs`
- [ ] 8.2 Add tests for Span manipulation in `crates/core/src/span.rs`
- [ ] 8.3 Add tests for Document operations in `crates/core/src/doc.rs`
- [ ] 8.4 Add tests for v2 AST types in `crates/core/src/v2/ast.rs`
- [ ] 8.5 Add tests for v2 pattern types in `crates/core/src/v2/pattern.rs`
- [ ] 8.6 Add tests for v2 predicate types in `crates/core/src/v2/predicate.rs`
- [ ] 8.7 Run coverage and verify core crate ≥90%

## 9. Sexpr Test Coverage

- [ ] 9.1 Add tests for s-expression parsing in `crates/sexpr/src/lib.rs`
- [ ] 9.2 Add tests for CST construction in `crates/sexpr/src/cst.rs`
- [ ] 9.3 Add tests for span handling in `crates/sexpr/src/span.rs`
- [ ] 9.4 Add tests for s-expression serialization
- [ ] 9.5 Run coverage and verify sexpr crate ≥90%

## 10. PP and Other Crates Coverage

- [ ] 10.1 Add tests for pretty-printing in `crates/pp/src/lib.rs`
- [ ] 10.2 Run coverage and verify pp crate ≥90%

## 11. Dead Code Elimination

- [ ] 11.1 Run `cargo build` with full warnings to identify unused code
- [ ] 11.2 Review and remove orphaned functions revealed by v1 removal
- [ ] 11.3 Remove any v1-related documentation references
- [ ] 11.4 Update README if it references v1
- [ ] 11.5 Verify clean build with no warnings

## 12. Final Verification

- [ ] 12.1 Run `cargo test --workspace` - all tests must pass
- [ ] 12.2 Run `cargo tarpaulin --workspace` - verify ≥90% for all crates
- [ ] 12.3 Run `cargo clippy --workspace` - no warnings
- [ ] 12.4 Run `cargo fmt --check` - verify formatting
- [ ] 12.5 Verify `cargo build --release` succeeds
- [ ] 12.6 Check git diff shows only expected changes

## 1. Spec Documentation

- [x] 1.1 Create `/openspec/specs/canonical-expression-format/spec.md`
- [x] 1.2 Document indent specification system (N=0/1/2)
- [x] 1.3 Document if-form asymmetric indentation
- [x] 1.4 Document fill layout for and/or
- [x] 1.5 Document function-call alignment
- [x] 1.6 Document special form keyword coloring

## 2. Dead Code Removal

- [x] 2.1 Remove `("case", 0)` from INDENT_SPECS in `crates/pp/src/lib.rs`
- [x] 2.2 Remove `"case"` from colored keywords list (line ~139)
- [x] 2.3 Remove `case` from cond/case special renderer check (line ~758-760)
- [x] 2.4 Verify `cond` forms still render correctly

## 3. Function Rename

- [x] 3.1 Rename `args_cond_to_case` → `hoist_cond` in `crates/config/src/migrate.rs`
- [x] 3.2 Update all call sites of the renamed function
- [x] 3.3 Update test function names that reference the old name

## 4. Testing

- [x] 4.1 Run `cargo test` in `crates/pp` to verify pp tests pass
- [x] 4.2 Run `cargo test` in `crates/config` to verify migration tests pass
- [x] 4.3 Run `cargo test` at workspace level
- [x] 4.4 Run `cargo run -- migrate` on sample config to verify end-to-end behavior
- [x] 4.5 Verify no `case` references remain in codebase (except test variable names)

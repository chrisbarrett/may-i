## 1. Core Type Migration - primitives.rs

- [x] 1.1 Create `crates/core/src/primitives.rs` with `Decision` enum and `Display` impl
- [x] 1.2 Add `ToDoc` trait to `primitives.rs`
- [x] 1.3 Add `Keyword` struct with validation to `primitives.rs`
- [x] 1.4 Update `crates/core/src/lib.rs` to re-export from `primitives`
- [x] 1.5 Compile core crate to verify no errors

## 2. Core Type Migration - context.rs

- [x] 2.1 Create `crates/core/src/context.rs` with `ContextValue` enum
- [x] 2.2 Add `ContextFacts` struct with `BTreeMap` storage to `context.rs`
- [x] 2.3 Implement `ContextFacts` methods: `has()`, `get()`, `get_scalar()`, `insert_present()`, `insert_scalar()`, `merge()`, `iter()`
- [x] 2.4 Add `Default` impl for `ContextFacts`
- [x] 2.5 Update `crates/core/src/lib.rs` to re-export from `context`
- [x] 2.6 Compile core crate to verify no errors

## 3. Core Type Migration - predicates.rs

- [x] 3.1 Create `crates/core/src/predicates.rs` with `FactPattern` enum
- [x] 3.2 Add `FactPattern` methods: `to_doc()`, `to_source()`, `is_literal()`
- [x] 3.3 Add `FactQuery` enum with `Presence` and `Value` variants
- [x] 3.4 Add `FactQuery` methods: `key()`, `to_doc()`, `to_source()`
- [x] 3.5 Update `crates/core/src/lib.rs` to re-export from `predicates`
- [x] 3.6 Compile core crate to verify no errors

## 4. Core Type Migration - pattern.rs updates

- [x] 4.1 Add `Expr<E>` enum to `crates/core/src/pattern.rs`
- [x] 4.2 Add `Expr` methods: `is_match()`, `is_wildcard()`, `find_effect()`, `to_doc()`
- [x] 4.3 Add `ExprBranch<E>` struct to `pattern.rs`
- [x] 4.4 Add `Quantifier` enum to `pattern.rs`
- [x] 4.5 Add `Quantifier` methods: `min()`, `is_repeating()`
- [x] 4.6 Update `crates/core/src/lib.rs` to re-export from `pattern`
- [x] 4.7 Compile core crate to verify no errors

## 5. Engine Type Migration

- [x] 5.1 Add `EvalResult` struct to `crates/engine/src/lib.rs`
- [x] 5.2 Add `EvalResult` methods: `new()`
- [x] 5.3 Update `crates/engine/src/eval.rs` imports (remove `types::` imports)
- [x] 5.4 Update `crates/engine/src/trace.rs` imports (remove `types::` imports)
- [~] 5.5 Compile engine crate to verify no errors - BLOCKED by legacy code deletion

## 6. Delete Legacy Code - Phase 1

- [x] 6.1 Delete `crates/core/src/types.rs` (3469 lines)
- [x] 6.2 Delete `crates/core/src/legacy/mod.rs` (12 lines)
- [x] 6.3 Remove legacy module from `crates/core/src/lib.rs`
- [x] 6.4 Compile core crate - expect failures due to missing imports

## 7. Delete Legacy Code - Phase 2 (Engine Visitors)

- [x] 7.1 Delete `crates/engine/src/visitors/code_execution.rs`
- [x] 7.2 Delete `crates/engine/src/visitors/function_call.rs`
- [x] 7.3 Delete `crates/engine/src/visitors/integration_tests.rs`
- [x] 7.4 Delete `crates/engine/src/visitors/mod.rs`
- [x] 7.5 Delete `crates/engine/src/visitors/read_builtin.rs`
- [x] 7.6 Delete `crates/engine/src/visitors/rule_match.rs`
- [x] 7.7 Delete `crates/engine/src/visitors/wrapper_unwrap.rs`
- [x] 7.8 Delete `crates/engine/src/visitors/dynamic_parts.rs`
- [x] 7.9 Remove `visitors` module from `crates/engine/src/lib.rs`
- [x] 7.10 Remove `evaluate_v1()` and `evaluate_with_context_v1()` from `crates/engine/src/lib.rs`
- [x] 7.11 Compile engine crate - expect failures due to missing imports

## 8. Update Imports - Config Crate

- [x] 8.1 Update `crates/config/src/io.rs`: change `use may_i_core::legacy::Config` to `use may_i_core::ast::Config`
- [x] 8.2 Compile config crate to verify no errors

## 9. Update Imports - Engine Check Module

- [x] 9.1 Update `crates/engine/src/check.rs`: replace legacy imports with new module paths
- [x] 9.2 Compile engine crate to verify no errors

## 10. Update Imports - Engine Matcher Module

- [x] 10.1 Update `crates/engine/src/matcher.rs`: replace legacy imports with new module paths
- [x] 10.2 Compile engine crate to verify no errors

## 11. Update Imports - Engine Annotate Module

- [x] 11.1 Update `crates/engine/src/annotate.rs`: replace legacy imports with new module paths
- [x] 11.2 Compile engine crate to verify no errors

## 12. Update Imports - Main CLI

- [x] 12.1 Update `src/cmd_claude_code_hook.rs`: replace `use may_i_core::{ContextFacts, EvalResult}` with correct paths
- [x] 12.2 Compile main crate to verify no errors

## 13. Test Migration - Simple Command Tests

- [x] 13.1 Update test config helper functions in `crates/engine/src/lib.rs` to return `ast::Config`
- [x] 13.2 Migrate `test_evaluate_simple_allow` to use v2 `evaluate()`
- [x] 13.3 Migrate `test_evaluate_simple_deny` to use v2 `evaluate()`
- [x] 13.4 Migrate `test_evaluate_no_matching_rule_ask` to use v2 `evaluate()`
- [x] 13.5 Migrate `test_evaluate_with_context_empty` to use v2 `evaluate()`
- [x] 13.6 Migrate `test_evaluate_assignment_command` to use v2 `evaluate()`
- [x] 13.7 Run simple command tests to verify they pass

## 14. Test Migration - Compound Command Helper

- [x] 14.1 Create `evaluate_compound()` helper function that parses shell command with `may_i_shell_parser::parse()`
- [x] 14.2 Implement recursive evaluation of `Command` enum variants
- [x] 14.3 Aggregate results using `Decision::most_restrictive()`
- [x] 14.4 Compile and verify helper works with a simple test case

## 15. Test Migration - Compound Command Tests

- [x] 15.1 Migrate `test_evaluate_sequence_commands` to use compound helper
- [x] 15.2 Migrate `test_evaluate_pipeline` to use compound helper
- [x] 15.3 Migrate `test_evaluate_subshell` to use compound helper
- [x] 15.4 Migrate `test_evaluate_background` to use compound helper
- [x] 15.5 Migrate `test_evaluate_if_statement_with_echo_condition` to use compound helper
- [x] 15.6 Migrate `test_evaluate_while_loop_with_echo` to use compound helper
- [x] 15.7 Migrate `test_evaluate_for_loop` to use compound helper
- [x] 15.8 Migrate `test_evaluate_case_statement` to use compound helper
- [x] 15.9 Migrate `test_evaluate_function_definition` to use compound helper
- [x] 15.10 Migrate `test_evaluate_and_list` to use compound helper
- [x] 15.11 Migrate `test_evaluate_or_list` to use compound helper
- [x] 15.12 Migrate `test_evaluate_brace_group` to use compound helper
- [x] 15.13 Migrate `test_evaluate_redirected_command` to use compound helper
- [x] 15.14 Migrate `test_evaluate_elif_branches` to use compound helper
- [x] 15.15 Migrate `test_evaluate_until_loop_with_echo` to use compound helper
- [x] 15.16 Migrate `test_evaluate_empty_input` to use compound helper
- [x] 15.17 Migrate `test_evaluate_whitespace_only` to use compound helper
- [x] 15.18 Migrate `test_evaluate_assignment_only` to use compound helper
- [x] 15.19 Migrate `test_evaluate_else_branch` to use compound helper
- [x] 15.20 Migrate `test_evaluate_no_else_branch_empty_config` to use compound helper
- [x] 15.21 Migrate `test_evaluate_empty_for_loop` to use compound helper
- [x] 15.22 Migrate `test_evaluate_sequence_with_deny` to use compound helper
- [x] 15.23 Migrate `test_evaluate_pipeline_returns_aggregate` to use compound helper
- [x] 15.24 Migrate `test_evaluate_deny_in_and_list` to use compound helper
- [x] 15.25 Migrate `test_evaluate_deny_in_or_list` to use compound helper
- [x] 15.26 Migrate `test_evaluate_background_with_deny` to use compound helper
- [x] 15.27 Migrate `test_evaluate_subshell_with_deny` to use compound helper
- [x] 15.28 Migrate `test_evaluate_deny_in_if_body` to use compound helper
- [x] 15.29 Migrate `test_evaluate_deny_in_for_body` to use compound helper
- [x] 15.30 Migrate `test_evaluate_deny_in_case_body` to use compound helper
- [x] 15.31 Migrate `test_evaluate_deny_in_function_body` to use compound helper
- [x] 15.32 Migrate `test_evaluate_deny_in_brace_group` to use compound helper
- [x] 15.33 Run all compound command tests to verify they pass

## 16. Final Verification

- [x] 16.1 Run full test suite: `cargo test`
- [x] 16.2 Verify all tests pass
- [x] 16.3 Run `cargo check` on entire workspace
- [ ] 16.4 Verify no compilation warnings
- [x] 16.5 Run `cargo fmt` to ensure formatting
- [ ] 16.6 Run `cargo clippy` to check for linting issues
- [x] 16.7 Verify final line count reduction (~4000 lines deleted)

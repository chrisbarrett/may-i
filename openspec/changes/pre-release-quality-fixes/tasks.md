## 1. Keyword-typed facts (runtime-context spec)

- [x] 1.1 Change `ContextFacts` internal representation from `BTreeMap<String, BTreeSet<String>>` to `BTreeMap<Keyword, BTreeSet<String>>` in `crates/core/src/context.rs`
- [x] 1.2 Update `ContextFacts` public methods (`has`, `get`, `contains`, `insert_scalar`, `push`, `insert_presence`) to accept `&Keyword` instead of `&str`/`impl Into<String>` — kept `&str`/`impl Into<String>` API with internal Keyword conversion for ergonomics
- [x] 1.3 Change `FactQuery::Presence` and `FactQuery::Value` key fields from `String` to `Keyword` in `crates/core/src/predicates.rs`
- [x] 1.4 Update all `ContextFacts` and `FactQuery` construction sites across the workspace (config parsing, engine evaluation, CLI commands, test helpers) to use `Keyword`
- [x] 1.5 Verify all tests pass with the new key types

## 2. Evaluator error handling

- [x] 2.1 Define `EvalError` enum with `UnresolvedPredicate { name: String }` variant in `crates/engine/src/lib.rs`, implementing `Display` and `std::error::Error`
- [x] 2.2 Change `evaluate`, `evaluate_effect`, and `evaluate_predicate` return types to `Result<T, EvalError>` in `crates/engine/src/eval.rs`
- [x] 2.3 Replace `panic!` at the `Named` predicate match arm with `Err(EvalError::UnresolvedPredicate { .. })`
- [x] 2.4 Update all callers of `evaluate` in the binary (`cmd_eval.rs`, `cmd_check.rs`, `cmd_claude_code_hook.rs`) to propagate the error with `?`
- [x] 2.5 Add test: evaluating a config with an unresolved predicate returns `Err`

## 3. Or expression short-circuit with bindings

- [x] 3.1 In `match_expr_with_binding` in `crates/engine/src/eval.rs`, change `Expr::Or` handling to return immediately after the first matching alternative instead of iterating all and merging
- [x] 3.2 Add test: `Or([Bind(:x, Wildcard), Bind(:y, Wildcard)])` against any value returns only `:x` in bound facts
- [x] 3.3 Verify existing Or-related tests still pass

## 4. Cond short-circuit

- [x] 4.1 In the `Cond` evaluation loop in `crates/engine/src/eval.rs`, stop evaluating predicates for branches after the first match; mark remaining branches as `Skipped`
- [x] 4.2 Add test: cond with three branches where first matches — verify second and third predicates are `Skipped` in fold output

## 5. Predicate serialization fix

- [x] 5.1 Change `Predicate::to_doc()` in `crates/core/src/ast.rs:314` from `Doc::atom("has")` to `Doc::atom("fact?")`
- [x] 5.2 Update any snapshot tests that reference the `has` keyword in serialized predicates

## 6. Claude Code hook fixes

- [x] 6.1 Add `validate_and_resolve` call in `src/cmd_claude_code_hook.rs` after loading config, before evaluation
- [x] 6.2 Replace `split_whitespace` command parsing with `shell_parser::parse` in `src/cmd_claude_code_hook.rs`
- [x] 6.3 Add integration test: hook with a config using `(define ...)` correctly resolves predicates
- [x] 6.4 Add integration test: hook with quoted arguments correctly preserves them

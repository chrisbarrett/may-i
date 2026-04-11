## 1. Remove inlining from resolve.rs

- [x] 1.1 Remove `resolve_predicates`, `resolve_rule_predicates`, `resolve_effect_predicates`, and `resolve_single_predicate` functions from `resolve.rs`
- [x] 1.2 Update `validate_and_resolve` to return the original (unresolved) rules after validation passes
- [x] 1.3 Update tests in `resolve.rs` that assert on inlined predicate shapes — assert Named references are preserved instead

## 2. Add binding environment to EvalContext

- [x] 2.1 Add a bindings field to `EvalContext` (map from name to predicate body, built from `Config.defines`)
- [x] 2.2 Update `EvalContext::new` and all call sites to supply the bindings
- [x] 2.3 Update `evaluate` and `evaluate_with_fold` entry points to build the env from `config.defines`

## 3. Resolve Predicate::Named at eval time

- [x] 3.1 Replace the `Predicate::Named` error arm in `evaluate_predicate_fold` with env lookup + recursive evaluation + `fold.predicate_named` call
- [x] 3.2 Add unit tests: Named match, Named no-match, transitive Named resolution
- [x] 3.3 Add unit test: missing define returns `EvalError::UnresolvedPredicate`

## 4. Update annotation fold for var breakout

- [x] 4.1 Update `predicate_named` in the annotation fold to produce a doc node with the define name and a nested child doc for the breakout
- [x] 4.2 Add a `VarRef` variant (or equivalent) to `Ann` enum carrying name, matched status, and child annotations

## 5. Render var breakout in trace output

- [x] 5.1 Update human-readable trace rendering (`src/output/mod.rs`) to display var breakouts as indented labelled sections
- [x] 5.2 Update JSON trace rendering (`src/output/json.rs`) to emit `type: "var_ref"` annotations with `name`, `matched`, and nested `body`
- [x] 5.3 Add rendering tests for both human-readable and JSON var breakout output

## 6. Integration tests

- [x] 6.1 End-to-end test: eval with defines produces correct decision (matches previous inlining behaviour)
- [x] 6.2 End-to-end test: `--json` trace output contains var_ref annotations with body breakout
- [x] 6.3 Update any existing integration tests that asserted on inlined predicate structure in trace output

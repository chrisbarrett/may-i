## 1. Archive superseded specs

- [ ] 1.1 Archive `context-aware-configuration` spec (replaced by fact-based system)
- [ ] 1.2 Archive `harness-adapters` spec (no adapter abstraction)
- [ ] 1.3 Archive `engine-property-tests`, `core-pattern-property-tests`, and `generator-implementation` specs (collapsed into testing-philosophy)

## 2. Apply new specs

- [ ] 2.1 Apply `top-level-evaluation-semantics` spec
- [ ] 2.2 Apply `set-based-facts` spec
- [ ] 2.3 Apply `via-fact-builtin` spec
- [ ] 2.4 Apply `migration-philosophy` spec
- [ ] 2.5 Apply `testing-philosophy` spec

## 3. Apply modified specs

- [ ] 3.1 Apply `unified-effect-evaluation` delta (command selector, not effect)
- [ ] 3.2 Apply `arg-pattern-evaluation` delta (remove At matcher)
- [ ] 3.3 Apply `partial-pattern-matching` delta (remove At references)
- [ ] 3.4 Apply `define-resolution` delta (bare symbols, not keywords)
- [ ] 3.5 Apply `fact-value-evaluation` delta (set-based model)
- [ ] 3.6 Apply `runtime-context` delta (set-based ContextFacts)
- [ ] 3.7 Apply `type-primitives` delta (remove ContextValue)
- [ ] 3.8 Apply `v2-expr-fact-binding` delta (bind site restrictions)
- [ ] 3.9 Apply `human-evaluation-trace` delta (has → fact? syntax)
- [ ] 3.10 Apply `opencode-context` delta (has/context → fact? syntax)
- [ ] 3.11 Apply `fact-predicates-in-args` delta (has → fact? syntax)

## 4. Remove At matcher from implementation

- [ ] 4.1 Remove `At` variant from `ArgPattern` enum in `crates/core/src/pattern.rs`
- [ ] 4.2 Remove `At` evaluation from `crates/engine/src/eval.rs`
- [ ] 4.3 Remove `(= N PATTERN)` parsing from `crates/config/src/pattern.rs`
- [ ] 4.4 Remove At-related tests
- [ ] 4.5 Run `cargo fmt` and verify all tests pass

## 5. Implement set-based facts

- [ ] 5.1 Change `ContextFacts` internal representation to `Map<Keyword, BTreeSet<String>>`
- [ ] 5.2 Remove `ContextValue` enum
- [ ] 5.3 Add `push` method for accumulating set values
- [ ] 5.4 Update `FactQuery::Value` evaluation to test set membership
- [ ] 5.5 Update `FactQuery::Presence` to check key existence
- [ ] 5.6 Update all call sites that construct or query `ContextFacts`
- [ ] 5.7 Run `cargo fmt` and verify all tests pass

## 6. Implement :via builtin

- [ ] 6.1 In `(may-i *)` evaluation, push current command name onto `:via` fact set before recursive eval
- [ ] 6.2 Add property tests for `:via` accumulation through nested unwrapping
- [ ] 6.3 Update trace output to reflect `:via` facts
- [ ] 6.4 Run `cargo fmt` and verify all tests pass

## 7. Enforce bind site restrictions

- [ ] 7.1 Add parser validation to reject `Expr::Bind` inside `forbidden` patterns
- [ ] 7.2 Add test for bind-in-forbidden rejection
- [ ] 7.3 Run `cargo fmt` and verify all tests pass

## 8. Enforce command selector restrictions

- [ ] 8.1 Verify parser rejects complex expressions (e.g., `positional`) in rule command position
- [ ] 8.2 Add test for rejection of non-selector forms in command position
- [ ] 8.3 Run `cargo fmt` and verify all tests pass

## 9. Final verification

- [ ] 9.1 Run full test suite (`cargo test`)
- [ ] 9.2 Run `cargo fmt`
- [ ] 9.3 Verify tarpaulin coverage is above threshold

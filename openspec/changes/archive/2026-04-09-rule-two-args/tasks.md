## 1. AST Change

- [x] 1.1 Change `Rule` struct in `crates/core/src/ast.rs`: `effects: Vec<Spanned<Effect>>` → `effect: Spanned<Effect>`
- [x] 1.2 Update `Rule::new` constructor to accept a single `Spanned<Effect>` instead of `Vec`
- [x] 1.3 Fix all compile errors in `crates/core/` from the struct change (Display, to_doc, tests)

## 2. Parser

- [x] 2.1 Update `parse_rule()` in `rule.rs` to enforce exactly one non-check body form after the command, with a helpful error message suggesting combinators
- [x] 2.2 Update rule parser tests: remove multi-effect tests, add arity error tests, add combinator tests

## 3. Evaluator

- [x] 3.1 Simplify `evaluate_rule` in `eval.rs`: replace effects loop with single-effect dispatch
- [x] 3.2 Update fold trait signatures in `fold.rs`: `rule_matched`/`rule_not_matched` take single `EffectOut` instead of `Vec<EffectOut>`
- [x] 3.3 Update `PureFold` implementation for new signatures
- [x] 3.4 Update `TracingFold` implementation for new signatures
- [x] 3.5 Fix all compile errors across engine crate (annotation, output, etc.)

## 4. Migration Pipeline

- [x] 4.1 Update `rule_inline_args` in `migrate.rs` to wrap inlined args + trailing effect in `(and ...)` when both are present
- [x] 4.2 Delete `rule_add_default_effect` — the evaluator's implicit `(or ... (effect :ask))` wrapping handles the default
- [x] 4.3 Update migration tests in `migrate.rs` and `migration_tests.rs` to expect single-effect output

## 5. Config and Docs

- [x] 5.1 Update `starter_config.lisp`: rewrite any multi-effect rules using combinators
- [x] 5.2 Update `REFERENCE.txt` rule syntax section
- [x] 5.3 Update rule parser doc comments and examples

## 6. Validation

- [x] 6.1 Run full test suite (`cargo test`) and fix any remaining failures
- [x] 6.2 Verify all 202 `may-i check` assertions pass

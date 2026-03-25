## 1. Core Types - Add Keyword Type

- [ ] 1.1 Create `Keyword` struct in `crates/core/src/types.rs` with inner String
- [ ] 1.2 Implement `Keyword::new()` constructor that validates strings start with `:`
- [ ] 1.3 Implement `Keyword::as_str()` accessor
- [ ] 1.4 Implement `Display` for Keyword
- [ ] 1.5 Implement `ToDoc` for Keyword (renders as atom)
- [ ] 1.6 Run `cargo test --package may-i-core keyword` - 5 tests should pass

## 2. Core Types - Add Expr::Bind Variant

- [ ] 2.1 Add `Bind { key: Keyword, expr: Box<Expr> }` variant to `Expr` enum
- [ ] 2.2 Add corresponding variant to `ExprF` base functor
- [ ] 2.3 Update `map`, `map_ref`, `map_ref_mut` implementations for new variant
- [ ] 2.4 Update `ToDoc` implementation for Expr::Bind (renders as `[:key expr]`)
- [ ] 2.5 Run `cargo test --package may-i-core expr_bind` - 1 test should pass

## 3. Config Parser - Support Bracket Notation

- [ ] 3.1 Update `parse_expr` in `crates/config/src/v2/pattern.rs` to handle `Sexpr::Vector`
- [ ] 3.2 Parse single-element vector `[:keyword]` as `Expr::Bind` with Wildcard
- [ ] 3.3 Parse two-element vector `[:keyword EXPR]` as `Expr::Bind` with parsed expr
- [ ] 3.4 Validate keyword using `Keyword::new()`
- [ ] 3.5 Run `cargo test --package may-i-config parse_positional_with_fact` - 4 tests should pass

## 4. Engine Evaluator - Handle Expr::Bind

- [ ] 4.1 Create `match_expr_with_binding()` that returns `(bool, ContextFacts)`
- [ ] 4.2 Handle `Expr::Bind` by evaluating inner expr AND capturing matched value
- [ ] 4.3 Update `match_positional_patterns` to use new function and accumulate facts
- [ ] 4.4 Thread bound facts through to continuation context
- [ ] 4.5 Update `match_expr` wrapper to discard facts for backward compatibility
- [ ] 4.6 Run `cargo test --package may-i-engine fact_binding` - 2 tests should pass

## 5. Migration - Preserve Bindings

- [ ] 5.1 Remove stripping code from `wrapper_to_rule` that converts `[:key *]` to `*`
- [ ] 5.2 Update test expectation in `test_wrapper_to_rule_with_capture_pattern`
- [ ] 5.3 Run `cargo test --package may-i-config test_wrapper_to_rule_preserves` - 1 test should pass

## 6. Integration & Verification

- [ ] 6.1 Run `cargo test` - all tests should pass
- [ ] 6.2 Run `cargo fmt` to format code
- [ ] 6.3 Verify migration test: `cargo test --package may-i-config migrate`
- [ ] 6.4 Run end-to-end check on starter config


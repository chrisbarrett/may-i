## 1. Core Types

- [ ] 1.1 Add `BoolExpr` enum to `crates/core/src/types.rs` with Has, And, Or, Not variants
- [ ] 1.2 Add `ArgMatcher::Has(BoolExpr)` variant
- [ ] 1.3 Create `MatcherCondPredicate` enum for polymorphic cond branches (Matcher, Expr, BoolExpr)
- [ ] 1.4 Update `ArgMatcher::Cond` to use new predicate type
- [ ] 1.5 Add `ArgMatcher::When/Unless/If` variants with first-class AST support
- [ ] 1.6 Add Display/Debug implementations for new types

## 2. Parser Updates

- [ ] 2.1 Create `parse_bool_expr` function in parser for BoolExpr parsing
- [ ] 2.2 Update `parse_arg_matcher` to recognize `has` keyword
- [ ] 2.3 Implement polymorphic branch parsing for cond/when/unless/if
- [ ] 2.4 Add context-sensitive parsing to reject `has` in Expr contexts
- [ ] 2.5 Update error messages for invalid predicate mixing
- [ ] 2.6 Add parser tests for new syntax forms

## 3. Matcher Evaluation

- [ ] 3.1 Thread `ContextFacts` through `expr_matches_resolved` signature
- [ ] 3.2 Update all call sites of `expr_matches_resolved` to pass facts
- [ ] 3.3 Add `bool_expr_matches` function for BoolExpr evaluation
- [ ] 3.4 Update `ArgMatcher` evaluation to handle new variants
- [ ] 3.5 Implement polymorphic branch evaluation
- [ ] 3.6 Add evaluation tests for mixed predicate scenarios

## 4. Annotator Updates

- [ ] 4.1 Thread `ContextFacts` through `annotate_expr_arg` signature
- [ ] 4.2 Add `annotate_bool_expr` function for BoolExpr annotations
- [ ] 4.3 Update matcher annotation for polymorphic branches
- [ ] 4.4 Add annotation tests for new AST nodes
- [ ] 4.5 Update trace output formatting for first-class when/unless/if

## 5. Integration & Testing

- [ ] 5.1 Update end-to-end tests with fact-predicate scenarios
- [ ] 5.2 Add integration test for wrapper facts + has predicates
- [ ] 5.3 Verify backward compatibility with existing configs
- [ ] 5.4 Add error handling tests for invalid predicate mixing
- [ ] 5.5 Update documentation with new syntax examples

## 6. Documentation & Cleanup

- [ ] 6.1 Update starter_config.lisp with examples of new syntax
- [ ] 6.2 Update README with fact predicate documentation
- [ ] 6.3 Add migration guide (even if no breaking changes)
- [ ] 6.4 Run full test suite
- [ ] 6.5 Verify trace output formatting

## 1. Core Types

- [x] 1.1 Add `BoolExpr` enum to `crates/core/src/types.rs` with Has, And, Or, Not variants
- [x] 1.2 Add `ArgMatcher::Has(BoolExpr)` variant
- [x] 1.3 Create `MatcherCondPredicate` enum for polymorphic cond branches (Matcher, Expr, BoolExpr)
- [x] 1.4 Update `ArgMatcher::Cond` to use new predicate type
- [x] 1.5 Add `ArgMatcher::When/Unless/If` variants with first-class AST support
- [x] 1.6 Add Display/Debug implementations for new types

## 2. Parser Updates

- [x] 2.1 Create `parse_bool_expr` function in parser for BoolExpr parsing
- [x] 2.2 Update `parse_arg_matcher` to recognize `has` keyword
- [x] 2.3 Implement polymorphic branch parsing for cond/when/unless/if
- [x] 2.4 Add context-sensitive parsing to reject `has` in Expr contexts
- [x] 2.5 Update error messages for invalid predicate mixing
- [x] 2.6 Add parser tests for new syntax forms

## 3. Matcher Evaluation

- [x] 3.1 Thread `ContextFacts` through matcher evaluation
- [x] 3.2 Update all call sites to pass facts through annotation
- [x] 3.3 Add `bool_expr_matches` function for BoolExpr evaluation
- [x] 3.4 Update `ArgMatcher` evaluation to handle new variants
- [x] 3.5 Implement polymorphic branch evaluation
- [x] 3.6 Add evaluation tests for mixed predicate scenarios

## 4. Annotator Updates

- [x] 4.1 Thread `ContextFacts` through `annotate_matcher` signature
- [x] 4.2 Add annotation support for BoolExpr via polymorphic predicates
- [x] 4.3 Update matcher annotation for polymorphic branches
- [x] 4.4 Add annotation tests for new AST nodes
- [x] 4.5 Update trace output formatting for first-class when/unless/if

## 5. Integration & Testing

- [x] 5.1 Update end-to-end tests with fact-predicate scenarios
- [x] 5.2 Add integration test for wrapper facts + has predicates
- [x] 5.3 Verify backward compatibility with existing configs
- [x] 5.4 Add error handling tests for invalid predicate mixing
- [x] 5.5 Update documentation with new syntax examples

## 6. Documentation & Cleanup

- [x] 6.1 Update starter_config.lisp with examples of new syntax
- [x] 6.2 Update README with fact predicate documentation
- [x] 6.3 Add migration guide (even if no breaking changes)
- [x] 6.4 Run full test suite
- [x] 6.5 Verify trace output formatting

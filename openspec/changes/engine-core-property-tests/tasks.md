# Tasks: Engine and Core Property Tests

## Phase 1: Infrastructure and Generators (crates/core)

### 1.1 Setup
- [ ] 1.1.1 Verify proptest is in core/Cargo.toml dev-dependencies
- [ ] 1.1.2 Create `crates/core/src/test_generators.rs` module
- [ ] 1.1.3 Add `#[cfg(test)] pub mod test_generators;` to lib.rs
- [ ] 1.1.4 Establish baseline coverage for core crate

### 1.2 Primitive Generators
- [ ] 1.2.1 Implement `any_keyword()` - generates valid Keyword values
- [ ] 1.2.2 Implement `any_decision()` - generates Decision enum values
- [ ] 1.2.3 Implement `any_context_value()` - generates ContextValue variants
- [ ] 1.2.4 Implement `any_context_facts()` - generates ContextFacts with 0-10 entries
- [ ] 1.2.5 Implement `any_fact_pattern(depth)` - recursive FactPattern generator
- [ ] 1.2.6 Implement `any_fact_query()` - generates FactQuery variants

### 1.3 Pattern Generators  
- [ ] 1.3.1 Implement `any_quantifier()` - generates Quantifier variants
- [ ] 1.3.2 Implement `any_expr<E>(depth, effect_gen)` - recursive Expr<E> generator
- [ ] 1.3.3 Implement `any_positional_arg(depth)` - generates PositionalArg
- [ ] 1.3.4 Implement `any_command_pattern(depth)` - recursive CommandPattern generator
- [ ] 1.3.5 Implement `any_arg_pattern(depth)` - recursive ArgPattern generator

## Phase 2: Core Property Tests

### 2.1 FactPattern Tests (predicates.rs)
- [ ] 2.1.1 Test: `is_literal()` returns true only for Literal variant
- [ ] 2.1.2 Test: `to_doc()` roundtrip (doc → parse → equal structure)
- [ ] 2.1.3 Test: `to_source()` produces valid syntax
- [ ] 2.1.4 Test: Literal pattern matches only exact string
- [ ] 2.1.5 Test: Wildcard pattern matches any string
- [ ] 2.1.6 Test: Regex pattern matches according to regex rules
- [ ] 2.1.7 Test: And pattern matches iff all sub-patterns match
- [ ] 2.1.8 Test: Or pattern matches iff any sub-pattern matches
- [ ] 2.1.9 Test: Not pattern matches iff sub-pattern doesn't match
- [ ] 2.1.10 Test: Complex nested patterns behave correctly

### 2.2 ContextFacts Tests (context.rs)
- [ ] 2.2.1 Test: `has()` returns true for inserted keys
- [ ] 2.2.2 Test: `has()` returns false for non-existent keys
- [ ] 2.2.3 Test: `get_scalar()` returns Some only for Scalar values
- [ ] 2.2.4 Test: `merge()` combines both contexts
- [ ] 2.2.5 Test: Later merge values overwrite earlier ones
- [ ] 2.2.6 Property: merge is associative (a.merge(b)).merge(c) == a.merge(b.merge(c))
- [ ] 2.2.7 Property: merge with empty is identity

### 2.3 Pattern Matching Tests (pattern.rs)
- [ ] 2.3.1 Test: CommandPattern::Literal matches exact command
- [ ] 2.3.2 Test: CommandPattern::Regex matches according to regex
- [ ] 2.3.3 Test: CommandPattern::Or matches if any sub-pattern matches
- [ ] 2.3.4 Test: Expr::is_match follows boolean logic for And/Or/Not
- [ ] 2.3.5 Test: Expr::find_effect returns correct effect for Cond branches
- [ ] 2.3.6 Test: Quantifier::min() returns correct minimum
- [ ] 2.3.7 Test: Quantifier::is_repeating() correct for all variants

## Phase 3: Engine Infrastructure

### 3.1 Setup
- [ ] 3.1.1 Verify proptest is in engine/Cargo.toml dev-dependencies
- [ ] 3.1.2 Create `crates/engine/src/test_generators.rs` module  
- [ ] 3.1.3 Re-export core generators and add engine-specific ones
- [ ] 3.1.4 Establish baseline coverage for engine crate

### 3.2 Effect Generators
- [ ] 3.2.1 Implement `any_terminal_effect()` - Allow/Ask/Deny variants
- [ ] 3.2.2 Implement `any_pattern_effect(depth)` - CommandPattern/ArgPattern effects
- [ ] 3.2.3 Implement `any_combinator_effect(depth)` - And/Or/Not with size limiting
- [ ] 3.2.4 Implement `any_conditional_effect(depth)` - When/Unless/If/Cond
- [ ] 3.2.5 Implement `any_may_i_effect(depth)` - Recursive MayI patterns
- [ ] 3.2.6 Implement `any_effect(depth)` - top-level effect generator with recursion limit

### 3.3 Predicate Generators
- [ ] 3.3.1 Implement `any_fact_predicate(depth)` - Fact queries
- [ ] 3.3.2 Implement `any_arg_predicate(depth)` - Arg pattern predicates  
- [ ] 3.3.3 Implement `any_named_predicate()` - Named references
- [ ] 3.3.4 Implement `any_predicate(depth)` - top-level predicate generator

### 3.4 Context Generators
- [ ] 3.4.1 Implement `any_eval_context()` - generates EvalContext with varied inputs
- [ ] 3.4.2 Implement `any_rule_set(size)` - generates vector of Rules
- [ ] 3.4.3 Implement `any_config(size)` - generates complete Config structures

## Phase 4: Engine Property Tests

### 4.1 Predicate Evaluation (eval.rs)
- [ ] 4.1.1 Test: evaluate_predicate never panics on valid inputs
- [ ] 4.1.2 Test: evaluate_predicate returns only Match or NoMatch
- [ ] 4.1.3 Property: And predicate matches iff all sub-predicates match
- [ ] 4.1.4 Property: Or predicate matches iff any sub-predicate matches
- [ ] 4.1.5 Property: Not predicate inverts Match/NoMatch
- [ ] 4.1.6 Property: And is associative
- [ ] 4.1.7 Property: Or is associative
- [ ] 4.1.8 Property: De Morgan's laws hold (not(a and b) == not a or not b)
- [ ] 4.1.9 Test: Fact query with presence checks works correctly
- [ ] 4.1.10 Test: Fact query with value patterns works correctly

### 4.2 Effect Evaluation (eval.rs)
- [ ] 4.2.1 Test: evaluate_effect never panics on valid inputs
- [ ] 4.2.2 Test: Terminal effects return correct Decision
- [ ] 4.2.3 Property: And returns Nil if any effect returns Nil
- [ ] 4.2.4 Property: And returns last result if all non-Nil
- [ ] 4.2.5 Property: Or returns first non-Nil result
- [ ] 4.2.6 Property: Or returns Nil if all Nil
- [ ] 4.2.7 Property: Not inverts Allow<->Nil, preserves Ask/Deny
- [ ] 4.2.8 Property: CommandPattern matches appropriate commands
- [ ] 4.2.9 Property: ArgPattern matches appropriate arguments
- [ ] 4.2.10 Property: When evaluates effect only if predicate matches
- [ ] 4.2.11 Property: Unless evaluates effect only if predicate doesn't match
- [ ] 4.2.12 Property: If chooses correct branch based on predicate
- [ ] 4.2.13 Property: Cond chooses first matching branch
- [ ] 4.2.14 Property: MayI recurses correctly with pattern match
- [ ] 4.2.15 Property: Recursion limit is respected

### 4.3 Full Evaluation (eval.rs)
- [ ] 4.3.1 Test: evaluate never panics on valid config/context
- [ ] 4.3.2 Test: evaluate returns valid EvalResult
- [ ] 4.3.3 Property: Empty rule set returns Ask
- [ ] 4.3.4 Property: First matching rule wins
- [ ] 4.3.5 Property: Facts are correctly bound and available
- [ ] 4.3.6 Property: Command context is correctly passed through
- [ ] 4.3.7 Property: Arg context is correctly passed through

### 4.4 Config Validation (check.rs)
- [ ] 4.4.1 Test: run_checks never panics on valid config
- [ ] 4.4.2 Test: Passing checks have passed=true
- [ ] 4.4.3 Test: Failing checks have passed=false
- [ ] 4.4.4 Test: Check with expected=Allow evaluates correctly
- [ ] 4.4.5 Test: Check with expected=Ask evaluates correctly
- [ ] 4.4.6 Test: Check with expected=Deny evaluates correctly
- [ ] 4.4.7 Property: Check result matches expected decision

## Phase 5: Unit Test Backfill

### 5.1 Hard-to-Generate Branches
- [ ] 5.1.1 Unit test: Named predicate panic path
- [ ] 5.1.2 Unit test: Invalid regex in pattern (error handling)
- [ ] 5.1.3 Unit test: Deeply nested effect overflow protection
- [ ] 5.1.4 Unit test: Malformed argument patterns (edge cases)
- [ ] 5.1.5 Unit test: Empty And/Or effects behavior
- [ ] 5.1.6 Unit test: Cond with empty branches

### 5.2 Integration Tests
- [ ] 5.2.1 Add integration test: Complex nested conditionals
- [ ] 5.2.2 Add integration test: Multiple fact bindings
- [ ] 5.2.3 Add integration test: Recursive MayI with context
- [ ] 5.2.4 Add integration test: Combined And/Or/Not in single rule

## Phase 6: Verification and Cleanup

### 6.1 Coverage Verification
- [ ] 6.1.1 Run tarpaulin and generate lcov report
- [ ] 6.1.2 Verify predicates.rs ≥90% coverage
- [ ] 6.1.3 Verify check.rs ≥90% coverage  
- [ ] 6.1.4 Verify pattern.rs (core) ≥90% coverage
- [ ] 6.1.5 Verify eval.rs ≥90% coverage
- [ ] 6.1.6 Identify and document remaining uncovered lines

### 6.2 Performance Verification
- [ ] 6.2.1 Run property tests 10 times, verify <10s per crate
- [ ] 6.2.2 Check memory usage during test runs
- [ ] 6.2.3 Verify no stack overflows on recursive generators
- [ ] 6.2.4 Tune generator parameters if needed

### 6.3 Quality Checks
- [ ] 6.3.1 Run `cargo fmt` on all modified files
- [ ] 6.3.2 Run `cargo clippy` and fix warnings
- [ ] 6.3.3 Verify all tests pass (`cargo test`)
- [ ] 6.3.4 Verify no compiler warnings
- [ ] 6.3.5 Review generator implementations for edge cases
- [ ] 6.3.6 Add doc comments to all generator functions

### 6.4 Documentation
- [ ] 6.4.1 Document generator strategies and parameters
- [ ] 6.4.2 Add module-level docs for test_generators.rs
- [ ] 6.4.3 Document shrink behavior for complex types
- [ ] 6.4.4 Update AGENTS.md with testing guidance

## Phase 7: Advanced (if time permits)

### 7.1 Shrinking Improvements
- [ ] 7.1.1 Implement custom shrink for Effect trees
- [ ] 7.1.2 Implement custom shrink for Predicate trees
- [ ] 7.1.3 Implement custom shrink for large ContextFacts

### 7.2 Additional Properties
- [ ] 7.2.1 Property: Evaluation is deterministic (same input → same output)
- [ ] 7.2.2 Property: Trace generation is complete
- [ ] 7.2.3 Property: No memory leaks in recursive evaluation
- [ ] 7.2.4 Property: Performance scales linearly with input size

### 7.3 Fuzzing Integration
- [ ] 7.3.1 Add cargo-fuzz harness for evaluator
- [ ] 7.3.2 Run fuzzer for 1 hour, fix any crashes
- [ ] 7.3.3 Add fuzz corpus to repository

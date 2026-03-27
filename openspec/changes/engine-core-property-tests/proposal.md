# Improve Engine and Core Test Coverage with Property Tests

## Why

The runtime evaluation engine has critical coverage gaps that pose significant risks:

- **eval.rs: 27.1%** (1,686 lines) - Core evaluation logic for effects and predicates
- **check.rs: 22.4%** (164 lines) - Config validation with embedded checks
- **predicates.rs: 0.0%** (156 lines) - Fact pattern matching and queries
- **pattern.rs: 46.8%** (516 lines) - Runtime argument pattern matching

These modules contain the actual authorization logic that makes security decisions. Untested paths could lead to:
- Incorrect authorization decisions (security vulnerabilities)
- Panics on edge case inputs (DoS)
- Undefined behavior in recursive evaluation

The existing test suite has only unit tests with specific examples. We need exhaustive property-based testing to exercise the combinatorial explosion of Effect × Predicate × Context combinations.

## What Changes

Add comprehensive property tests to the engine and core crates using proptest with recursive generators for:

1. **Effect evaluation** - Generate arbitrary Effect trees and verify:
   - Never panics on valid inputs
   - Always returns valid EffectResult
   - Algebraic properties (And/Or/Not follow boolean logic)
   - Idempotency (same input → same output)

2. **Predicate evaluation** - Generate arbitrary Predicate trees and verify:
   - Returns only Match or NoMatch
   - Boolean algebra properties hold
   - Fact queries resolve correctly

3. **Pattern matching** - Generate ArgPattern/Expr trees and verify:
   - Matching is deterministic
   - Bindings are captured correctly
   - Continuations work as expected

4. **Config validation** - Generate Config structures and verify:
   - Checks run without panic
   - Embedded check commands evaluate correctly

## Capabilities

### New Capabilities

- `engine-property-tests`: Exhaustive property tests for effect/predicate evaluation
- `core-pattern-property-tests`: Property tests for pattern matching and binding
- `core-predicate-property-tests`: Property tests for fact query evaluation
- `evaluator-fuzzing`: Input generation for edge case discovery

### Modified Capabilities

- None (test-only changes)

## Impact

- **Security**: Reduced risk of authorization bypasses through untested code paths
- **Reliability**: No panics on edge case inputs
- **Maintainability**: Property tests verify behavior, not structure
- **Coverage**: Target >90% coverage in eval.rs, check.rs, predicates.rs, pattern.rs
- **CI time**: Moderate increase (~5-10s per crate with property tests)
- **Dependencies**: No new runtime deps; proptest already available

## Success Criteria

- eval.rs: ≥90% coverage (from 27.1%)
- check.rs: ≥90% coverage (from 22.4%)
- predicates.rs: ≥90% coverage (from 0%)
- pattern.rs (core): ≥90% coverage (from 46.8%)
- All property tests complete in <10s per crate
- Zero property test failures on 10,000+ generated cases
- No panics discovered (or all panics documented as bugs and fixed)

## Notes

- Moderate proptest configuration (256 cases default, 10,000 for CI)
- Unit tests only for branches that are genuinely hard to generate
- Priority order: predicates.rs → check.rs → pattern.rs → eval.rs
- Generators must respect recursion limits to avoid stack overflow

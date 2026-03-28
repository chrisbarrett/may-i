# Specification: Engine Property Tests

## Overview

Property-based testing for the may-i evaluation engine ensuring correctness, completeness, and absence of panics.

## Invariants

### Evaluation Safety
- **INV-EVAL-001**: `evaluate_effect` never panics on valid Effect inputs
- **INV-EVAL-002**: `evaluate_predicate` never panics on valid Predicate inputs
- **INV-EVAL-003**: `evaluate` never panics on valid Config/Context inputs
- **INV-EVAL-004**: All evaluation functions return valid results for any input within type bounds

### Type Safety
- **INV-TYPE-001**: `evaluate_predicate` returns only `Match` or `NoMatch`
- **INV-TYPE-002**: `evaluate_effect` returns only `Decision` or `Nil`
- **INV-TYPE-003**: `Decision` variants are always one of `Allow`, `Ask`, `Deny`

### Boolean Algebra
- **INV-BOOL-001**: `And` predicate matches iff all sub-predicates match
- **INV-BOOL-002**: `Or` predicate matches iff any sub-predicate matches
- **INV-BOOL-003**: `Not` predicate inverts `Match`/`NoMatch`
- **INV-BOOL-004**: De Morgan's laws: `not(a and b) == (not a) or (not b)`
- **INV-BOOL-005**: De Morgan's laws: `not(a or b) == (not a) and (not b)`

### Effect Combinators
- **INV-EFF-001**: `And` effect returns `Nil` if any sub-effect returns `Nil`
- **INV-EFF-002**: `And` effect returns last result if all sub-effects non-`Nil`
- **INV-EFF-003**: `Or` effect returns first non-`Nil` result
- **INV-EFF-004**: `Or` effect returns `Nil` if all sub-effects return `Nil`
- **INV-EFF-005**: `Not` inverts `Allow` to `Nil` and `Nil` to `Allow`
- **INV-EFF-006**: `Not` preserves `Ask` and `Deny` unchanged

### Conditionals
- **INV-COND-001**: `When` evaluates effect only if predicate matches
- **INV-COND-002**: `Unless` evaluates effect only if predicate doesn't match
- **INV-COND-003**: `If` evaluates `then_effect` if predicate matches, else `else_effect`
- **INV-COND-004**: `Cond` evaluates first effect whose predicate matches

### Pattern Matching
- **INV-PAT-001**: `CommandPattern::Literal` matches only exact command string
- **INV-PAT-002**: `CommandPattern::Regex` matches according to regex rules
- **INV-PAT-003**: `CommandPattern::Or` matches if any sub-pattern matches
- **INV-PAT-004**: `ArgPattern` matching is deterministic
- **INV-PAT-005**: `Expr::Bind` captures matched values correctly

### Context and Facts
- **INV-CTX-001**: `ContextFacts::has` returns true for inserted keys
- **INV-CTX-002**: `ContextFacts::get_scalar` returns `Some` only for `Scalar` values
- **INV-CTX-003**: `ContextFacts::merge` combines both contexts
- **INV-CTX-004**: Merge with empty context is identity

### Recursion and Limits
- **INV-REC-001**: Recursion depth limit is respected
- **INV-REC-002**: Exceeding recursion limit returns `Ask` with reason

### Determinism
- **INV-DET-001**: Evaluation is deterministic (same input → same output)
- **INV-DET-002**: Property tests produce reproducible failures

## Acceptance Criteria

1. All invariants verified by property tests
2. 256 test cases per property (proptest default)
3. Maximum 30 second timeout per test
4. All tests pass consistently (no flaky tests)

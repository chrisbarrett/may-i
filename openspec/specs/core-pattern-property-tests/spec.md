# Specification: Core Pattern Property Tests

## Overview

Property-based testing for pattern matching and fact predicates in the may-i core crate.

## Invariants

### FactPattern Matching
- **INV-FP-001**: `FactPattern::Literal` matches only exact string
- **INV-FP-002**: `FactPattern::Wildcard` matches any string
- **INV-FP-003**: `FactPattern::Regex` matches according to compiled regex
- **INV-FP-004**: `FactPattern::And` matches iff all patterns match
- **INV-FP-005**: `FactPattern::Or` matches iff any pattern matches
- **INV-FP-006**: `FactPattern::Not` matches iff inner pattern doesn't match

### FactPattern Serialization
- **INV-FP-SER-001**: `to_doc()` produces valid Doc representation
- **INV-FP-SER-002**: `to_source()` produces parseable source code
- **INV-FP-SER-003**: Roundtrip: parse(to_source(pattern)) preserves semantics

### FactQuery Evaluation
- **INV-FQ-001**: `Presence` query matches if key exists in context
- **INV-FQ-002**: `Value` query matches if key exists and value matches pattern
- **INV-FQ-003**: `Value` query with non-existent key returns no match

### Expression Matching
- **INV-EXPR-001**: `Expr::Literal` matches only exact text
- **INV-EXPR-002**: `Expr::Regex` matches according to regex
- **INV-EXPR-003**: `Expr::Wildcard` matches any text
- **INV-EXPR-004**: `Expr::And` matches iff all sub-expressions match
- **INV-EXPR-005**: `Expr::Or` matches iff any sub-expression matches
- **INV-EXPR-006**: `Expr::Not` matches iff sub-expression doesn't match
- **INV-EXPR-007**: `Expr::Cond` matches if any branch test matches

### Expression Binding
- **INV-BIND-001**: `Expr::Bind` captures matched value
- **INV-BIND-002**: Nested binds capture at appropriate levels
- **INV-BIND-003**: Bind in `And` captures if expression matches
- **INV-BIND-004**: Bind in `Or` captures only if that branch matches

### Command Patterns
- **INV-CMD-001**: `CommandPattern::Literal` is exact match
- **INV-CMD-002**: `CommandPattern::Regex` uses regex matching
- **INV-CMD-003**: `CommandPattern::Or` is disjunction of sub-patterns

### Argument Patterns
- **INV-ARG-001**: `ArgPattern::Positional` matches positional arguments
- **INV-ARG-002**: `ArgPattern::Exact` requires exact argument count
- **INV-ARG-003**: `ArgPattern::Anywhere` matches token anywhere in args
- **INV-ARG-004**: `ArgPattern::Forbidden` fails if token appears
- **INV-ARG-005**: `ArgPattern::At` matches specific position

### Quantifiers
- **INV-QUANT-001**: `One` requires exactly one match
- **INV-QUANT-002**: `Optional` matches zero or one
- **INV-QUANT-003**: `OneOrMore` matches one or more
- **INV-QUANT-004**: `ZeroOrMore` matches zero or more
- **INV-QUANT-005**: `min()` returns correct minimum count

## Acceptance Criteria

1. All pattern matching invariants verified by property tests
2. Coverage for predicates.rs ≥90%
3. Coverage for pattern.rs ≥90%
4. All property tests complete in <10 seconds

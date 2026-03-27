## ADDED Requirements

### Requirement: Expr type available in pattern module
The `Expr<E>` enum (Literal, Regex, Wildcard, And, Or, Not, Cond, Bind) SHALL be defined in `crates/core/src/pattern.rs` and re-exported from `may_i_core`.

#### Scenario: Expr can match strings
- **WHEN** an `Expr::Literal("test")` is matched against "test"
- **THEN** it returns true

#### Scenario: Expr supports generic effect type
- **WHEN** `Expr<Effect>` is used in pattern matching
- **THEN** it compiles and works with the Effect type parameter

### Requirement: ExprBranch type available in pattern module
The `ExprBranch<E>` struct SHALL be defined in `crates/core/src/pattern.rs` and re-exported from `may_i_core`.

#### Scenario: ExprBranch can be constructed
- **WHEN** creating an `ExprBranch { test, effect }`
- **THEN** it stores both the test expression and the effect

### Requirement: Quantifier enum available in pattern module
The `Quantifier` enum (One, Optional, OneOrMore, ZeroOrMore) SHALL be defined in `crates/core/src/pattern.rs` and re-exported from `may_i_core`.

#### Scenario: Quantifier reports minimum count
- **WHEN** calling `Quantifier::OneOrMore.min()`
- **THEN** it returns 1

#### Scenario: Quantifier identifies repeating
- **WHEN** calling `Quantifier::ZeroOrMore.is_repeating()`
- **THEN** it returns true

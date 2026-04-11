## MODIFIED Requirements

### Requirement: ArgPattern uses Ordered variant
The `ArgPattern` enum SHALL have an `Ordered { mode: MatchMode, patterns: Vec<PositionalArg>, continuation: Option<Box<Effect>> }` variant replacing the separate `Positional` and `Exact` variants.

#### Scenario: Constructing a positional pattern
- **WHEN** creating what was previously `ArgPattern::Positional { patterns, continuation }`
- **THEN** it SHALL be `ArgPattern::Ordered { mode: MatchMode::Positional, patterns, continuation }`

#### Scenario: Constructing an exact pattern
- **WHEN** creating what was previously `ArgPattern::Exact { patterns, continuation }`
- **THEN** it SHALL be `ArgPattern::Ordered { mode: MatchMode::Exact, patterns, continuation }`

#### Scenario: MatchMode enum
- **WHEN** inspecting the MatchMode enum
- **THEN** it SHALL have exactly two variants: `Positional` and `Exact`

## ADDED Requirements

### Requirement: MatchMode enum available in pattern module
The `MatchMode` enum (Positional, Exact) SHALL be defined in `crates/core/src/pattern.rs` and re-exported from `may_i_core`.

#### Scenario: MatchMode can be compared
- **WHEN** comparing `MatchMode::Positional == MatchMode::Exact`
- **THEN** it SHALL return false

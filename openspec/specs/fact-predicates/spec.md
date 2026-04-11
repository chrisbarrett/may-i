## ADDED Requirements

### Requirement: FactPattern enum available in predicates module
The `FactPattern` enum (Literal, Wildcard, Regex, And, Or, Not) SHALL be defined in `crates/core/src/predicates.rs` and re-exported from `may_i_core`.

#### Scenario: FactPattern can match literal values
- **WHEN** `FactPattern::Literal("prod")` is matched against "prod"
- **THEN** it returns true

#### Scenario: FactPattern supports boolean combinators
- **WHEN** `FactPattern::And(vec![p1, p2])` is matched
- **THEN** it returns true only if both patterns match

### Requirement: FactQuery enum available in predicates module
The `FactQuery` enum (Presence, Value) SHALL be defined in `crates/core/src/predicates.rs` and re-exported from `may_i_core`. `FactQuery::Presence` SHALL carry only the `key` field — no `vector_syntax` field.

#### Scenario: FactQuery can check key presence
- **WHEN** `FactQuery::Presence { key }` is evaluated
- **THEN** it checks if the key exists in context

#### Scenario: FactQuery can check key value
- **WHEN** `FactQuery::Value { key, pattern }` is evaluated
- **THEN** it checks if the key's value matches the pattern

#### Scenario: No vector_syntax in domain model
- **WHEN** constructing a `FactQuery::Presence`
- **THEN** only the `key` field SHALL be required

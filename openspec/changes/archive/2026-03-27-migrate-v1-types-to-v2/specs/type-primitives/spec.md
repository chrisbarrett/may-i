## ADDED Requirements

### Requirement: Decision enum available in primitives module
The `Decision` enum (Allow, Ask, Deny) SHALL be defined in `crates/core/src/primitives.rs` and re-exported from `may_i_core`.

#### Scenario: Decision can be imported from primitives
- **WHEN** code imports `use may_i_core::Decision`
- **THEN** the `Decision` enum is available for use

### Requirement: ToDoc trait available in primitives module
The `ToDoc` trait SHALL be defined in `crates/core/src/primitives.rs` and re-exported from `may_i_core`.

#### Scenario: ToDoc can be implemented for custom types
- **WHEN** a type implements the `ToDoc` trait
- **THEN** it can be converted to a `Doc` representation

### Requirement: Keyword type available in primitives module
The `Keyword` struct (validated string starting with `:`) SHALL be defined in `crates/core/src/primitives.rs` and re-exported from `may_i_core`.

#### Scenario: Keyword validates colon prefix
- **WHEN** creating a Keyword with `Keyword::new(":test")`
- **THEN** it succeeds and stores the string

#### Scenario: Keyword rejects non-colon strings
- **WHEN** creating a Keyword with `Keyword::new("invalid")`
- **THEN** it returns an error

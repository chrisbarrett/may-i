## ADDED Requirements

### Requirement: ContextFacts available in context module
The `ContextFacts` struct SHALL be defined in `crates/core/src/context.rs` and re-exported from `may_i_core`.

#### Scenario: ContextFacts can store presence facts
- **WHEN** calling `context.insert_present(":via/ssh")`
- **THEN** the key is marked as present

#### Scenario: ContextFacts can store scalar values
- **WHEN** calling `context.insert_scalar(":env", "prod")`
- **THEN** the key stores the scalar value

#### Scenario: ContextFacts can be queried
- **WHEN** calling `context.get(":env")` on a populated context
- **THEN** it returns the stored value

### Requirement: ContextValue enum available in context module
The `ContextValue` enum (Present, Scalar) SHALL be defined in `crates/core/src/context.rs`.

#### Scenario: ContextValue distinguishes presence from value
- **WHEN** matching on `ContextValue::Present`
- **THEN** it indicates the key exists without a value

#### Scenario: ContextValue stores scalar strings
- **WHEN** matching on `ContextValue::Scalar(s)`
- **THEN** `s` contains the stored string value

## MODIFIED Requirements

### Requirement: ContextFacts available in context module
The `ContextFacts` struct SHALL be defined in `crates/core/src/context.rs` and re-exported from `may_i_core`. (CHANGED: internal representation is now `Map<Keyword, Set<String>>` instead of Present/Scalar enum)

#### Scenario: ContextFacts can store presence facts
- **WHEN** inserting presence fact `:via/ssh`
- **THEN** the key SHALL exist in the store with an empty set

#### Scenario: ContextFacts can store scalar values
- **WHEN** inserting fact `[:env "prod"]`
- **THEN** the key `:env` SHALL contain set `{"prod"}`

#### Scenario: ContextFacts can accumulate set values
- **WHEN** inserting `[:via "sudo"]` then `[:via "ssh"]`
- **THEN** the key `:via` SHALL contain set `{"sudo", "ssh"}`

#### Scenario: ContextFacts can be queried for presence
- **WHEN** calling `context.contains_key(":env")` on a populated context
- **THEN** it SHALL return true if the key exists

#### Scenario: ContextFacts can be queried for membership
- **WHEN** calling `context.contains(":via", "ssh")` on a context with `:via` = `{"sudo", "ssh"}`
- **THEN** it SHALL return true

### Requirement: ContextValue enum removed
The `ContextValue` enum (Present, Scalar) SHALL be removed. All facts are stored as sets. (CHANGED: previously distinguished Present from Scalar; now unified as sets)

#### Scenario: No variant distinction
- **WHEN** storing any fact
- **THEN** the internal representation SHALL be a `Set<String>` at the given key

## MODIFIED Requirements

### Requirement: ContextFacts available in context module
The `ContextFacts` struct SHALL be defined in `crates/core/src/context.rs` and re-exported from `may_i_core`. The internal representation SHALL be `BTreeMap<Keyword, BTreeSet<String>>`. All public methods accepting keys SHALL accept `&Keyword` (not `&str`). (CHANGED: key type is `Keyword`, not `String`, enforcing the colon-prefix invariant at compile time)

#### Scenario: ContextFacts can store presence facts
- **WHEN** inserting presence fact with key `Keyword::new(":via/ssh")`
- **THEN** the key SHALL exist in the store with an empty set

#### Scenario: ContextFacts can store scalar values
- **WHEN** inserting fact with key `Keyword::new(":env")` and value `"prod"`
- **THEN** the key `:env` SHALL contain set `{"prod"}`

#### Scenario: ContextFacts can accumulate set values
- **WHEN** inserting `Keyword::new(":via")` with value `"sudo"` then `"ssh"`
- **THEN** the key `:via` SHALL contain set `{"sudo", "ssh"}`

#### Scenario: ContextFacts can be queried for presence
- **WHEN** calling `context.has(&kw)` where `kw` is a `Keyword`
- **THEN** it SHALL return true if the key exists

#### Scenario: ContextFacts can be queried for membership
- **WHEN** calling `context.contains(&kw, "ssh")` where `kw = Keyword::new(":via")`
- **THEN** it SHALL return true if `"ssh"` is in the set at `:via`

#### Scenario: Bare strings rejected at compile time
- **WHEN** attempting to call `context.has("via/ssh")` with a `&str`
- **THEN** it SHALL fail to compile because the method requires `&Keyword`

### Requirement: FactQuery uses Keyword-typed keys
The `FactQuery` enum variants `Presence` and `Value` SHALL use `Keyword` for their `key` field instead of `String`. (CHANGED: key field type from `String` to `Keyword`)

#### Scenario: FactQuery::Presence uses Keyword
- **WHEN** constructing `FactQuery::Presence { key }`
- **THEN** `key` SHALL be of type `Keyword`

#### Scenario: FactQuery::Value uses Keyword
- **WHEN** constructing `FactQuery::Value { key, pattern }`
- **THEN** `key` SHALL be of type `Keyword`

## MODIFIED Requirements

### Requirement: FactQuery::Presence evaluates against stored facts
`FactQuery::Presence` SHALL return Match when the queried key exists in the fact store (the set may be empty or populated). (CHANGED: fact store is now set-based; presence checks key existence regardless of set contents)

#### Scenario: Key present with values
- **GIVEN** fact store contains `:via` = `{"sudo", "ssh"}`
- **WHEN** evaluating `FactQuery::Presence { key: ":via" }`
- **THEN** it SHALL return Match

#### Scenario: Key present with empty set
- **GIVEN** fact store contains `:client/claude-code` with empty set
- **WHEN** evaluating `FactQuery::Presence { key: ":client/claude-code" }`
- **THEN** it SHALL return Match

#### Scenario: Key absent
- **GIVEN** fact store does not contain `:via`
- **WHEN** evaluating `FactQuery::Presence { key: ":via" }`
- **THEN** it SHALL return NoMatch

### Requirement: FactQuery::Value evaluates as set-membership test
`FactQuery::Value` SHALL return Match when the queried key exists and the pattern matches any member of the set at that key. (CHANGED: previously matched a single scalar value; now tests set membership)

#### Scenario: Literal matches a set member
- **GIVEN** fact store contains `:via` = `{"sudo", "ssh"}`
- **WHEN** evaluating `FactQuery::Value { key: ":via", pattern: Literal("ssh") }`
- **THEN** it SHALL return Match

#### Scenario: Literal does not match any member
- **GIVEN** fact store contains `:via` = `{"sudo"}`
- **WHEN** evaluating `FactQuery::Value { key: ":via", pattern: Literal("ssh") }`
- **THEN** it SHALL return NoMatch

#### Scenario: Regex matches any set member
- **GIVEN** fact store contains `:ssh/host` = `{"prod-server-01"}`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Regex("^prod-") }`
- **THEN** it SHALL return Match

#### Scenario: Wildcard matches if set is non-empty
- **GIVEN** fact store contains `:ssh/host` = `{"prod-1"}`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Wildcard }`
- **THEN** it SHALL return Match

#### Scenario: Wildcard does not match empty set
- **GIVEN** fact store contains `:client/claude-code` with empty set
- **WHEN** evaluating `FactQuery::Value { key: ":client/claude-code", pattern: Wildcard }`
- **THEN** it SHALL return NoMatch

#### Scenario: Missing key returns NoMatch
- **GIVEN** fact store does not contain `:ssh/host`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Literal("prod") }`
- **THEN** it SHALL return NoMatch

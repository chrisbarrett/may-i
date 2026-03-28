## ADDED Requirements

### Requirement: All facts are sets internally
The fact store SHALL represent all facts as `Map<Keyword, Set<String>>`. There is no distinction between presence facts, scalar facts, and multi-valued facts at the storage level.

#### Scenario: Singleton fact
- **WHEN** inserting fact `[:ssh/host "prod-1"]`
- **THEN** the store SHALL contain key `:ssh/host` with set `{"prod-1"}`

#### Scenario: Presence fact is a key with empty set
- **WHEN** inserting presence fact `:client/claude-code`
- **THEN** the store SHALL contain key `:client/claude-code` with an empty set

#### Scenario: Multi-valued fact
- **WHEN** inserting `[:via "sudo"]` then `[:via "ssh"]`
- **THEN** the store SHALL contain key `:via` with set `{"sudo", "ssh"}`

### Requirement: Presence query checks key existence
`(fact? :key)` SHALL return Match if the key exists in the fact store (regardless of whether the set is empty or populated).

#### Scenario: Presence fact matches
- **GIVEN** fact store contains `:client/claude-code` (empty set)
- **WHEN** evaluating `(fact? :client/claude-code)`
- **THEN** it SHALL return Match

#### Scenario: Missing key does not match
- **GIVEN** fact store does not contain `:client/claude-code`
- **WHEN** evaluating `(fact? :client/claude-code)`
- **THEN** it SHALL return NoMatch

### Requirement: Value query is set-membership test
`(fact? [:key "val"])` SHALL return Match if `"val"` is a member of the set stored at `:key`.

#### Scenario: Singleton membership
- **GIVEN** fact store contains `:ssh/host` = `{"prod-1"}`
- **WHEN** evaluating `(fact? [:ssh/host "prod-1"])`
- **THEN** it SHALL return Match

#### Scenario: Multi-value membership
- **GIVEN** fact store contains `:via` = `{"sudo", "ssh"}`
- **WHEN** evaluating `(fact? [:via "ssh"])`
- **THEN** it SHALL return Match

#### Scenario: Non-member does not match
- **GIVEN** fact store contains `:via` = `{"sudo"}`
- **WHEN** evaluating `(fact? [:via "ssh"])`
- **THEN** it SHALL return NoMatch

### Requirement: Regex query tests any set member
`(fact? [:key (regex "...")])` SHALL return Match if any member of the set matches the regex.

#### Scenario: Regex matches a member
- **GIVEN** fact store contains `:ssh/host` = `{"prod-server-01"}`
- **WHEN** evaluating `(fact? [:ssh/host (regex "^prod-")])`
- **THEN** it SHALL return Match

#### Scenario: Regex matches none
- **GIVEN** fact store contains `:ssh/host` = `{"dev-server-01"}`
- **WHEN** evaluating `(fact? [:ssh/host (regex "^prod-")])`
- **THEN** it SHALL return NoMatch

### Requirement: CLI --fact flag produces singleton sets
`--fact :key=value` SHALL insert a singleton set `{value}` at `key`. `--fact :key` SHALL insert the key with an empty set (presence).

#### Scenario: Scalar fact from CLI
- **WHEN** invoking `may-i eval --fact :opencode/agent=plan`
- **THEN** the fact store SHALL contain `:opencode/agent` = `{"plan"}`

#### Scenario: Presence fact from CLI
- **WHEN** invoking `may-i eval --fact :client/opencode`
- **THEN** the fact store SHALL contain `:client/opencode` with an empty set

### Requirement: Bind produces singleton sets
When `Expr::Bind` captures a value during pattern matching, it SHALL insert a singleton set at the bound key.

#### Scenario: Bind captures scalar
- **GIVEN** pattern `(positional [:ssh/host *])` and args `["prod-1"]`
- **WHEN** the bind matches
- **THEN** the fact store SHALL contain `:ssh/host` = `{"prod-1"}`

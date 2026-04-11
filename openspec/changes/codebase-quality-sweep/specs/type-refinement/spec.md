## ADDED Requirements

### Requirement: TerminalDecision replaces Allow/Ask/Deny variants
The `Effect` enum SHALL have a single `Terminal { decision: Decision, reason: Option<String> }` variant instead of separate `Allow`, `Ask`, and `Deny` variants.

#### Scenario: Constructing a terminal effect
- **WHEN** creating an allow effect with reason "safe command"
- **THEN** it SHALL be `Effect::Terminal { decision: Decision::Allow, reason: Some("safe command".into()) }`

#### Scenario: Pattern matching terminal effects
- **WHEN** matching on an Effect value that is a terminal decision
- **THEN** a single match arm `Effect::Terminal { decision, reason }` SHALL handle all three decision types

### Requirement: PositionalMatchKind enum replaces covarying Options
`PositionalElementDetail` SHALL use a `PositionalMatchKind` enum instead of three covarying `Option` fields (`binding`, `expr_match`, `cond_branch_index`).

#### Scenario: Bind match
- **WHEN** a positional element matches via binding
- **THEN** the kind SHALL be `PositionalMatchKind::Bind(BindDetail { .. })`

#### Scenario: Expr match
- **WHEN** a positional element matches via literal/regex
- **THEN** the kind SHALL be `PositionalMatchKind::ExprMatch(ExprMatchDetail { .. })`

#### Scenario: Cond match
- **WHEN** a positional element matches via cond branch
- **THEN** the kind SHALL be `PositionalMatchKind::Cond { branch_index, detail }`

#### Scenario: Wildcard match
- **WHEN** a positional element matches via wildcard
- **THEN** the kind SHALL be `PositionalMatchKind::Wildcard`

### Requirement: Ordered ArgPattern merges Positional and Exact
`ArgPattern` SHALL have a single `Ordered { mode: MatchMode, patterns, continuation }` variant replacing the separate `Positional` and `Exact` variants.

#### Scenario: Positional matching
- **WHEN** an `Ordered` pattern has `mode: MatchMode::Positional`
- **THEN** it SHALL match if all patterns match, ignoring extra args

#### Scenario: Exact matching
- **WHEN** an `Ordered` pattern has `mode: MatchMode::Exact`
- **THEN** it SHALL match only if all patterns match AND all args are consumed

### Requirement: BindDetail.key uses Keyword type
`BindDetail.key` SHALL be of type `Keyword` instead of `String`.

#### Scenario: BindDetail construction
- **WHEN** constructing a BindDetail for key `:ssh/host`
- **THEN** the key field SHALL be a `Keyword` value

### Requirement: vector_syntax removed from FactQuery domain model
`FactQuery::Presence` SHALL NOT carry a `vector_syntax` field. Syntax representation SHALL be handled at the config parser layer only.

#### Scenario: FactQuery construction in tests
- **WHEN** constructing a `FactQuery::Presence` in test code
- **THEN** no `vector_syntax` field SHALL be required

#### Scenario: Serialisation preserves syntax choice
- **WHEN** the config parser encounters `[:key]` vector syntax
- **THEN** it SHALL record the syntax choice locally for round-trip serialisation without storing it in the FactQuery

### Requirement: LoadedConfig wraps Config with presentation data
A `LoadedConfig` struct in the binary crate SHALL carry `config`, `source_text`, and `pre_migration_forms`. The core `Config` type SHALL NOT carry these fields.

#### Scenario: Config in core has no presentation fields
- **WHEN** inspecting `may_i_core::ast::Config`
- **THEN** it SHALL NOT have `source_text` or `pre_migration_forms` fields

#### Scenario: Binary loads config into LoadedConfig
- **WHEN** the binary loads a config file
- **THEN** it SHALL produce a `LoadedConfig` containing the parsed config and metadata

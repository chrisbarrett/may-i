## ADDED Requirements

### Requirement: Bind is valid in positional, exact, and anywhere but not forbidden
`Expr::Bind` SHALL be accepted by the parser inside `positional`, `exact`, and `anywhere` patterns. The parser SHALL reject `Expr::Bind` inside `forbidden` patterns with a clear error.

#### Scenario: Bind in positional
- **WHEN** parsing `(positional [:ssh/host *])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in exact
- **WHEN** parsing `(exact [:env "prod"])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in anywhere
- **WHEN** parsing `(anywhere [:git/branch (regex "^(main|master)$")])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in forbidden rejected
- **WHEN** parsing `(forbidden [:key *])`
- **THEN** the parser SHALL reject it with an error explaining bind is not valid in forbidden patterns

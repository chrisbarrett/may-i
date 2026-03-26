## ADDED Requirements

### Requirement: Keyword type validates namespaced keys
The system SHALL provide a `Keyword` type that validates strings start with `:` at construction time.

#### Scenario: Valid keyword construction
- **WHEN** creating a Keyword with `:ssh/host`
- **THEN** construction succeeds
- **AND** the keyword's string representation is `:ssh/host`

#### Scenario: Invalid keyword rejected
- **WHEN** creating a Keyword with `ssh` (no colon)
- **THEN** construction fails with an error message explaining keywords must start with `:`

#### Scenario: Empty string rejected
- **WHEN** creating a Keyword with empty string
- **THEN** construction fails

#### Scenario: Whitespace-only rejected
- **WHEN** creating a Keyword with whitespace only
- **THEN** construction fails

### Requirement: Expr::Bind variant represents fact binding
The system SHALL provide an `Expr::Bind` variant with a `Keyword` key and inner `Expr` pattern.

#### Scenario: Bind with wildcard
- **WHEN** creating `Expr::Bind { key: ":ssh/host", expr: Wildcard }`
- **THEN** the expression matches any value
- **AND** captures the matched value as fact `:ssh/host`

#### Scenario: Bind with literal
- **WHEN** creating `Expr::Bind { key: ":env", expr: Literal("prod") }`
- **THEN** the expression matches only the literal "prod"
- **AND** captures the value "prod" as fact `:env` on match

#### Scenario: Bind with regex
- **WHEN** creating `Expr::Bind { key: ":ssh/host", expr: Regex("^prod-") }`
- **THEN** the expression matches values starting with "prod-"
- **AND** captures the full matched value as fact `:ssh/host`

### Requirement: Parser supports bracket notation for binding
The v2 pattern parser SHALL recognize `[:keyword]` and `[:keyword EXPR]` syntax as `Expr::Bind`.

#### Scenario: Simple bracket notation
- **WHEN** parsing `(positional [:ssh/host])`
- **THEN** it produces `Expr::Bind { key: ":ssh/host", expr: Wildcard }`

#### Scenario: Bracket with explicit wildcard
- **WHEN** parsing `(positional [:ssh/host *])`
- **THEN** it produces `Expr::Bind { key: ":ssh/host", expr: Wildcard }`
- **AND** this is equivalent to `[:ssh/host]`

#### Scenario: Bracket with literal
- **WHEN** parsing `(positional [:env "prod"])`
- **THEN** it produces `Expr::Bind { key: ":env", expr: Literal("prod") }`

#### Scenario: Bracket with regex
- **WHEN** parsing `(positional [:ssh/host (regex "^prod-")])`
- **THEN** it produces `Expr::Bind { key: ":ssh/host", expr: Regex("^prod-") }`

#### Scenario: Bracket in positional with continuation
- **WHEN** parsing `(positional [:ssh/host] . (may-i *))`
- **THEN** the positional pattern includes the binding
- **AND** the continuation receives the bound fact

### Requirement: Evaluator captures bound facts
The expression evaluator SHALL return matched facts alongside the match result when evaluating `Expr::Bind`.

#### Scenario: Wildcard binding captures value
- **GIVEN** input value "prod-server-01"
- **WHEN** matching against `Expr::Bind { key: ":ssh/host", expr: Wildcard }`
- **THEN** match succeeds
- **AND** captured facts contain `:ssh/host = "prod-server-01"`

#### Scenario: Literal binding only captures on match
- **GIVEN** input value "prod"
- **WHEN** matching against `Expr::Bind { key: ":env", expr: Literal("prod") }`
- **THEN** match succeeds
- **AND** captured facts contain `:env = "prod"`

#### Scenario: Literal binding fails - no capture
- **GIVEN** input value "dev"
- **WHEN** matching against `Expr::Bind { key: ":env", expr: Literal("prod") }`
- **THEN** match fails
- **AND** no facts are captured

#### Scenario: Regex binding captures full value
- **GIVEN** input value "prod-server-01"
- **WHEN** matching against `Expr::Bind { key: ":ssh/host", expr: Regex("^prod-") }`
- **THEN** match succeeds
- **AND** captured facts contain `:ssh/host = "prod-server-01"` (full value, not just match)

#### Scenario: Bound facts flow to continuation
- **GIVEN** a rule `(rule "ssh" (positional [:ssh/host] . (may-i *)) :effect :deny)`
- **AND** the command is `ssh prod-server journalctl`
- **WHEN** evaluating the positional pattern
- **THEN** `:ssh/host = "prod-server"` is bound
- **AND** the continuation `(may-i *)` evaluates with this fact in context

### Requirement: Migration preserves fact bindings
The v1-to-v2 migration SHALL preserve `[:keyword EXPR]` bindings instead of stripping them.

#### Scenario: Wrapper with binding migrates correctly
- **GIVEN** v1 input `(wrapper "ssh" (positional [:ssh/host *] :command+args))`
- **WHEN** migrating to v2
- **THEN** output contains `(rule "ssh" (positional [:ssh/host] . (may-i *)) :effect :ask)`
- **AND** the `[:ssh/host]` binding is preserved

#### Scenario: Wrapper with binding to specific pattern
- **GIVEN** v1 input `(wrapper "ssh" (positional [:ssh/host (regex "^prod-")] :command+args))`
- **WHEN** migrating to v2
- **THEN** output contains `(rule "ssh" (positional [:ssh/host (regex "^prod-")] . (may-i *)) :effect :ask)`
- **AND** the full binding expression is preserved


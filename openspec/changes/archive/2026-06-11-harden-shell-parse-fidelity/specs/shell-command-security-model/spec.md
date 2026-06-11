## ADDED Requirements

### Requirement: Leading `!` is pipeline negation

A bare `!` at the start of a pipeline SHALL be treated as pipeline negation:
the inner pipeline SHALL be evaluated as if the `!` were absent, and `!` SHALL
NOT be evaluated as a command name. Negation is authorisation-transparent —
`may-i` decides on command structure, not exit status — so it SHALL NOT alter
the decision the inner pipeline would otherwise produce.

Negation SHALL be recognised only at pipeline-start position. A `!` appearing
elsewhere — as a command argument (`find . ! -name x`) or inside a test
(`[ ! -f x ]`) — SHALL remain a literal argument and be carried into that
command's argv unchanged.

#### Scenario: Negated pipeline evaluates the inner command

- **WHEN** the input is `! kill -0 %1`
- **AND** `kill` is denied
- **THEN** the decision SHALL be `:deny`
- **AND** the reason SHALL name `kill`, not `!`

#### Scenario: Negation does not change the decision

- **WHEN** the input is `! rm -rf /`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny` (identical to evaluating `rm -rf /`)

#### Scenario: Negated command with no rule reports the real command name

- **WHEN** the input is `! kubectl get pods`
- **AND** no rule matches `kubectl`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL be `No rule for command `kubectl`` — never naming `!`

#### Scenario: `!` as an argument is literal

- **WHEN** the input is `find . ! -name foo`
- **AND** `find` is allowed
- **THEN** `!` SHALL NOT be treated as negation or as a command name
- **AND** the decision SHALL be `:allow` (the `!` is part of `find`'s argv)

### Requirement: Unterminated substitutions are not recursed into

The evaluator SHALL NOT recurse into the swallowed text of an unterminated
substitution. When a command substitution (`$(…)`, `` `…` ``) or other
expansion carries an Error-severity diagnostic because it is unterminated, that
text is not a command and MUST NOT be extracted as an embedded command. The
Error-severity floor (see "Error-severity diagnostics floor decision at ask")
SHALL own the outcome, so the reported reason is the
`parse error: <kind message> at line L, column C: '<excerpt>'` form and is never
a fabricated `No rule for command …` clause derived from the swallowed text.

#### Scenario: Unterminated command substitution is not recursed into

- **WHEN** the input is `grep -n "x$(y" file`
- **AND** `grep` is allowed
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL start with `parse error: unterminated command substitution`
- **AND** the reason SHALL NOT contain `No rule for command`

#### Scenario: Well-formed substitution still recurses

- **WHEN** the input is `echo $(rm -rf /)`
- **AND** `echo` is allowed and `rm` is denied
- **THEN** the decision SHALL be `:deny` (the embedded `rm` is still evaluated)

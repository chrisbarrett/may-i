## ADDED Requirements

### Requirement: Process-substitution inner commands are evaluated

The evaluator SHALL extract and evaluate the inner command of a process
substitution (`<(…)`, `>(…)`) wherever the substitution appears — as a command
argument or as a redirect target — so that a command inside a process
substitution is authorised in the same way as one inside `$(…)`. The inner
command MUST NOT be dropped from the parsed command.

#### Scenario: Process substitution in argument position is evaluated

- **WHEN** the input is `cat <(rm -rf /danger)`
- **AND** a rule asks about recursive `rm`
- **THEN** the inner `rm` SHALL be evaluated and the decision SHALL be at least
  `:ask`
- **AND** the `rm` SHALL NOT be absent from evaluation

#### Scenario: Process substitution as a redirect target is evaluated

- **WHEN** the input is `while read x; do :; done < <(rm -rf /danger)`
- **AND** a rule asks about recursive `rm`
- **THEN** the inner `rm` SHALL be evaluated and the decision SHALL be at least
  `:ask`

### Requirement: Process-substitution parsing does not consume following tokens

Parsing a process substitution SHALL stop at its matching `)` and SHALL NOT
consume tokens that follow it. A loop redirected from a process substitution
inside a brace group, subshell, or function body SHALL NOT cause commands after
the loop to be dropped; those commands SHALL remain in the parsed command and be
evaluated. Where any input still cannot be placed in the grammar, the parser
SHALL emit an Error-severity diagnostic (which floors the decision to `:ask` per
"Error-severity diagnostics floor decision at ask") rather than silently
discarding tokens.

#### Scenario: Command after a process-substitution-redirected loop survives

- **WHEN** the input is `f() { while read x; do :; done < <(find .); rm -rf /danger; }`
- **AND** a rule asks about recursive `rm`
- **THEN** the trailing `rm -rf /danger` SHALL be evaluated and the decision
  SHALL be at least `:ask`
- **AND** `rm` SHALL NOT be silently dropped

#### Scenario: Process substitution does not desync a subshell

- **WHEN** the input is `( while read x; do :; done < <(find .); rm x )`
- **THEN** the trailing `rm` SHALL appear in the evaluated command

#### Scenario: Command-substitution redirect target is unaffected

- **WHEN** the input is `f() { while read x; do :; done < "$(echo f)"; rm x; }`
- **THEN** the trailing `rm` SHALL be evaluated (regression guard — this case
  already parses correctly)

# via-fact-builtin Specification

## Purpose

How the automatic `:via` fact is populated during wrapper recursion: each `(authorise)` recurse pushes the wrapping command name onto the `:via` set, accumulating across nested wrappers. Set semantics mean order does not matter for membership tests. `:via` is the only automatic fact; named facts require explicit `(positional [:k *] …)` binding in the pattern.

## Requirements

### Requirement: may-i pushes command name onto :via set
When `(may-i *)` triggers recursive evaluation, the evaluator SHALL automatically push the current command name onto the `:via` fact set before evaluating the inner command.

#### Scenario: Single wrapper
- **GIVEN** rule `(rule "sudo" (positional . (may-i *)) :effect (effect :deny))`
- **WHEN** evaluating `sudo rm -rf /`
- **THEN** the inner evaluation of `rm -rf /` SHALL have `:via` = `{"sudo"}`

#### Scenario: Nested wrappers accumulate
- **GIVEN** rules for `sudo` and `ssh` using `(may-i *)`
- **WHEN** evaluating `sudo ssh prod-1 rm -rf /`
- **THEN** the inner evaluation of `rm` SHALL have `:via` = `{"sudo", "ssh"}`

#### Scenario: Order does not matter for set membership
- **GIVEN** `:via` = `{"sudo", "ssh"}` from nested unwrapping
- **WHEN** evaluating `(fact? [:via "ssh"])`
- **THEN** it SHALL return Match regardless of unwrapping order

### Requirement: :via is the only automatically pushed fact
Only the `:via` key SHALL be automatically populated by `(may-i *)`. All other facts (e.g., `:ssh/host`) require explicit `Expr::Bind` in the pattern.

#### Scenario: Bind facts are not automatic
- **GIVEN** rule `(rule "ssh" (positional . (may-i *)) :effect (effect :deny))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}`
- **AND** the inner evaluation SHALL NOT have `:ssh/host` (no bind in pattern)

#### Scenario: Bind plus automatic via
- **GIVEN** rule `(rule "ssh" (positional [:ssh/host *] . (may-i *)) :effect (effect :deny))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}` and `:ssh/host` = `{"prod-1"}`

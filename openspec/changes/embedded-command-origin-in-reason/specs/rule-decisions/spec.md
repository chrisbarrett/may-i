## ADDED Requirements

### Requirement: Embedded-substitution origin is named in the reason

The engine SHALL annotate the aggregate `:ask` reason when that reason
originates from an embedded command substitution (backtick or dollar-paren)
inside an outer command. The annotation MUST identify both the inner command,
the outer command, and the substitution form, in a single line.

When the outer command's name is itself dynamic (the outer first word is
also a substitution), the annotation MAY omit the outer command name and
instead say "embedded substitution".

Reasons that do not originate from a substitution SHALL be unchanged. The
annotation SHALL NOT contain a literal newline character.

#### Scenario: Backtick substitution inside grep

- **GIVEN** a config with no rule for `:rebuild`
- **WHEN** evaluating ``grep -nE "x|`:rebuild`y" file``
- **THEN** the result SHALL be `:ask`
- **AND** the reason SHALL be ``No rule for command `:rebuild` (backtick substitution in `grep`)``

#### Scenario: Dollar-paren substitution inside echo

- **GIVEN** a config with no rule for `:rebuild`
- **WHEN** evaluating `echo "$(:rebuild)"`
- **THEN** the result SHALL be `:ask`
- **AND** the reason SHALL be ``No rule for command `:rebuild` ($(...) substitution in `echo`)``

#### Scenario: Top-level invocation reason is unchanged

- **GIVEN** a config with no rule for `kubectl`
- **WHEN** evaluating `kubectl get pods`
- **THEN** the reason SHALL be exactly ``No rule for command `kubectl` ``
- **AND** the reason SHALL NOT contain the substring `substitution in`

#### Scenario: Nested substitution does not double-wrap

- **GIVEN** a config with no rule for `:rebuild`
- **WHEN** evaluating ``echo "$(grep -nE `:rebuild` file)"``
- **THEN** the reason SHALL contain exactly one ` substitution in ` clause

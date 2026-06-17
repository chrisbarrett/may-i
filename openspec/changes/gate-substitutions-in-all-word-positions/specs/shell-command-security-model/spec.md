## ADDED Requirements

### Requirement: Embedded command substitutions are evaluated in every word position

The evaluator SHALL extract and evaluate an embedded command substitution
regardless of the syntactic position the word containing it occupies. A command
substitution, a backtick substitution, and a process substitution each execute a
command, so each SHALL be evaluated whether it appears in a simple-command word,
a redirect target, the value of a bare assignment, the iteration words of a
`for` loop, or the subject and pattern words of a `case`. An embedded command
SHALL NOT resolve to `:allow` merely because the word that contains it is never
reached by decomposition.

Arithmetic expansion (`$(( … ))`) runs no command and SHALL NOT produce an
embedded-command unit.

#### Scenario: Substitution in a bare assignment value is evaluated

- **WHEN** the input is `z=$(rm -rf /); echo done`
- **AND** a rule denies `rm` and a rule allows `echo`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`
- **AND** the `rm` SHALL NOT be silently allowed

#### Scenario: Substitution in for-loop words is evaluated

- **WHEN** the input is `for x in $(rm -rf /); do echo "$x"; done`
- **AND** a rule denies `rm`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Substitution in a case subject is evaluated

- **WHEN** the input is `case $(rm -rf /) in *) echo hi;; esac`
- **AND** a rule denies `rm`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Coverage holds across arbitrary inputs

- **WHEN** any shell command is decomposed
- **THEN** every command, backtick, and process substitution present in the
  input SHALL be represented by an embedded-command evaluation unit

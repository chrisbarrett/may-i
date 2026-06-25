## MODIFIED Requirements

### Requirement: Embedded command substitutions are evaluated in every word position

The evaluator SHALL extract and evaluate an embedded command substitution
regardless of the syntactic position the word containing it occupies. A command
substitution, a backtick substitution, and a process substitution each execute a
command, so each SHALL be evaluated whether it appears in a simple-command word,
a redirect target, the value of a bare assignment, the iteration words of a
`for` loop, the subject and pattern words of a `case`, the operand of a
parameter-expansion operator (the `value`/`pattern`/`replacement`/`message`
text of forms such as `${x:-…}`, `${x:+…}`, `${x:=…}`, `${x:?…}`, `${x#…}`,
`${x%…}`, `${x/…/…}`), the operand of a **patterned case-conversion**
(`${x^pat}`, `${x^^pat}`, `${x,pat}`, `${x,,pat}`), the operand of a
**transform or unrecognised operator** (`${x@Q}`, `${x@a}`, and any operator the
lexer does not structure), the name operand of an **indirect/nameref expansion**
(`${!name}`), or a **glob bracket expression** (`[…]`). An embedded command
SHALL NOT resolve to `:allow` merely because the word that contains it is never
reached by decomposition, and SHALL NOT be lost because the form that contains
it is parsed as an unresolved flat value.

A flat or unresolved parameter-expansion form (patterned case-conversion,
transform/unknown operator, indirect/nameref) and a glob bracket expression
remain **unresolved** for the purpose of argv resolution — they still floor an
`:allow` as an expansion-bearing word — but the command and backtick
substitutions they contain SHALL each be represented by an embedded-command
evaluation unit.

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

#### Scenario: Substitution in a parameter-expansion default value is evaluated

- **WHEN** the input is `echo ${x:-$(rm -rf /)}`
- **AND** a rule denies `rm` and a rule allows `echo`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`
- **AND** the `rm` SHALL NOT be silently allowed

#### Scenario: Substitution in a parameter-expansion pattern is evaluated

- **WHEN** the input is `echo ${x#$(rm -rf /)}`
- **AND** a rule denies `rm`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Substitution in a patterned case-conversion operand is evaluated

- **WHEN** the input is `echo ${x^$(rm -rf /)}`
- **AND** a rule denies `rm` and a rule allows `echo`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`
- **AND** the same SHALL hold for `${x,,$(rm -rf /)}`

#### Scenario: Substitution in a transform or unknown operator operand is evaluated

- **WHEN** the input is `echo ${x@Q$(rm -rf /)}`
- **AND** a rule denies `rm`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Substitution in an indirect/nameref operand is evaluated

- **WHEN** the input is `echo ${!$(rm -rf /)}`
- **AND** a rule denies `rm`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Substitution in a glob bracket is evaluated

- **WHEN** the input is `echo [$(rm -rf /)]`
- **AND** a rule denies `rm` and a rule allows `echo`
- **THEN** the decision SHALL be `:deny` from the embedded `rm`

#### Scenario: Coverage holds across arbitrary inputs

- **WHEN** any shell command is decomposed
- **THEN** every command, backtick, and process substitution present in the
  input — including those inside parameter-expansion operands of every operator
  form (default/alternative/assign/error/strip/replace/substring/patterned
  case-conversion/transform/indirect), and those inside glob bracket
  expressions — SHALL be represented by an embedded-command evaluation unit

## ADDED Requirements

### Requirement: Indirect and nameref expansions are recognised, not flattened

An indirect or nameref parameter expansion SHALL be recognised as a distinct,
structured expansion shape rather than collapsed into an opaque flat string.
This covers `${!name}` (the value of the variable *named by* `$name`), the list
forms `${!prefix*}` / `${!prefix@}`, and the array-key form `${!arr[@]}`.

The form SHALL remain **unresolved**: its resolved value is unknown, so a word
containing it is expansion-bearing and floors an `:allow`. Recognition SHALL NOT
introduce value resolution.

The literal name appearing inside an indirect expansion is **not** the variable
that is read (the read variable is named indirectly), so the literal name SHALL
NOT be reported as a secret-read of that name. Any command or backtick
substitution embedded in the name operand SHALL still be gated per the embedded
command substitution requirement.

#### Scenario: Indirect expansion floors an allow

- **WHEN** the input is `echo ${!ref}`
- **AND** a rule allows `echo`
- **THEN** the word containing `${!ref}` SHALL be treated as expansion-bearing
- **AND** the decision SHALL NOT resolve to `:allow` on the strength of the
  literal expansion text

#### Scenario: Indirect expansion does not taint its literal name

- **WHEN** the input is `echo ${!AWS_TOKEN}`
- **AND** a rule denies reads of the `AWS_TOKEN` environment variable
- **THEN** the literal name `AWS_TOKEN` SHALL NOT be treated as a secret-read
  (the variable actually read is the one *named by* `$AWS_TOKEN`)

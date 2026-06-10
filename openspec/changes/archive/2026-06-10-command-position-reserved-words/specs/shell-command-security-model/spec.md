## ADDED Requirements

### Requirement: Reserved words are recognised only in command-word position

The parser SHALL recognise a reserved word (`if`, `then`, `elif`, `else`, `fi`,
`for`, `in`, `while`, `until`, `do`, `done`, `case`, `esac`, `function`, `{`,
`}`) as that keyword only when it appears in command-word position: the first
word of the input, or the first word after a command separator or operator
(`;`, `&`, newline, `|`, `||`, `&&`, `(`), or after a list-introducing keyword
(`do`, `then`, `else`, `elif`, `{`). A word whose spelling matches a reserved
word but which appears as a command argument SHALL be treated as a literal
`Word` and preserved in the command's argv. No argument SHALL be silently
dropped because it spells a reserved word.

#### Scenario: Keyword spelling as a trailing argument is literal

- **WHEN** the input is `find . -name done`
- **THEN** the command SHALL be a Simple command with words `find`, `.`,
  `-name`, `done`
- **AND** `ParseResult.diagnostics` SHALL be empty

#### Scenario: Multiple keyword-spelled arguments are preserved

- **WHEN** the input is `echo do done fi`
- **THEN** the command SHALL be a Simple command with words `echo`, `do`,
  `done`, `fi`

#### Scenario: Keyword spelling as a flag value is literal

- **WHEN** the input is `kubectl get pods in default`
- **THEN** the command SHALL be a Simple command retaining `in` and `default`

#### Scenario: Compound commands still parse

- **WHEN** the input is `while true; do echo hi; done`
- **THEN** the leading `while`, the `do`, and the closing `done` SHALL be
  recognised as keywords and the command SHALL parse as a while-loop

#### Scenario: Decision is made on the full command

- **WHEN** the input is `rm -rf done`
- **AND** a rule decides `rm` based on its arguments
- **THEN** the rule SHALL see `-rf` and `done` as arguments (not a truncated
  `rm -rf`)

### Requirement: The parser never silently discards tokens

The parser SHALL NOT drop tokens it cannot place in the grammar. When a reserved
word appears where the grammar cannot accept it, the parser SHALL emit an
Error-severity diagnostic, which by the existing floor (see "Error-severity
diagnostics floor decision at ask") forces the decision to at least `:ask`.

#### Scenario: Misplaced keyword floors the decision

- **WHEN** the input is a command in which a reserved word appears in command
  position but cannot be placed in any valid construct (e.g. a stray `done`
  with no opening `do`)
- **THEN** an Error-severity diagnostic SHALL be emitted
- **AND** the decision SHALL be at least `:ask`
- **AND** no portion of the input SHALL be silently discarded from evaluation

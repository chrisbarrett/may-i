## ADDED Requirements

### Requirement: Parser returns diagnostics alongside AST

The `parse()` function SHALL return a `ParseResult` containing both the
best-effort AST and a list of `ParseDiagnostic` values. The AST output for any
given input SHALL be identical to the current parser output.

#### Scenario: Well-formed input has no diagnostics

- **WHEN** the input is `echo hello`
- **THEN** `ParseResult.diagnostics` SHALL be empty
- **AND** `ParseResult.command` SHALL be a Simple command

#### Scenario: Malformed input has diagnostics and AST

- **WHEN** the input is `echo "unterminated`
- **THEN** `ParseResult.diagnostics` SHALL contain one entry
- **AND** `ParseResult.command` SHALL still be a valid AST

### Requirement: Unterminated quotes produce Error-severity diagnostics

Unterminated single quotes, double quotes, and backticks SHALL produce
diagnostics with `Severity::Error` because the parse boundary is ambiguous.

#### Scenario: Unterminated double quote

- **WHEN** the input is `echo "hello; rm -rf /`
- **THEN** a diagnostic with kind `UnterminatedDoubleQuote` SHALL be emitted
- **AND** the span SHALL point to the opening `"` character
- **AND** the severity SHALL be `Error`

#### Scenario: Unterminated single quote

- **WHEN** the input is `echo 'hello`
- **THEN** a diagnostic with kind `UnterminatedSingleQuote` SHALL be emitted
- **AND** the severity SHALL be `Error`

#### Scenario: Unterminated backtick

- **WHEN** the input is `` echo `hello ``
- **THEN** a diagnostic with kind `UnterminatedBacktick` SHALL be emitted
- **AND** the severity SHALL be `Error`

### Requirement: Unterminated substitutions produce Error-severity diagnostics

Unterminated `$(...)`, `$((...))`  and `${...}` constructs SHALL produce
diagnostics with `Severity::Error`.

#### Scenario: Unterminated command substitution

- **WHEN** the input is `echo $(rm -rf /`
- **THEN** a diagnostic with kind `UnterminatedCommandSubstitution` SHALL be
  emitted
- **AND** the severity SHALL be `Error`

#### Scenario: Unterminated arithmetic

- **WHEN** the input is `echo $((1+2`
- **THEN** a diagnostic with kind `UnterminatedArithmetic` SHALL be emitted
- **AND** the severity SHALL be `Error`

### Requirement: Missing closing keywords produce Warning-severity diagnostics

Missing `fi`, `done`, `esac`, `)`, and `}` SHALL produce diagnostics with
`Severity::Warning` because the command body is unambiguous.

#### Scenario: Missing fi

- **WHEN** the input is `if true; then echo hello`
- **THEN** a diagnostic with kind `MissingClosingKeyword("fi")` SHALL be emitted
- **AND** the severity SHALL be `Warning`

#### Scenario: Missing done

- **WHEN** the input is `while true; do echo hello`
- **THEN** a diagnostic with kind `MissingClosingKeyword("done")` SHALL be
  emitted
- **AND** the severity SHALL be `Warning`

### Requirement: Error-severity diagnostics floor decision at ask

When `ParseResult.diagnostics` contains any `Error`-severity items, the
evaluator SHALL set the final decision to at least `:ask`, regardless of what
the rule evaluation produced.

#### Scenario: Allowed command with parse error

- **WHEN** the input is `echo "hello; rm -rf /`
- **AND** `echo` is allowed
- **THEN** the decision SHALL be `:ask` (not `:allow`)
- **AND** the reason SHALL mention the parse diagnostic

#### Scenario: Denied command with parse error

- **WHEN** the input is `rm "unterminated`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny` (floor is `:ask`, but `:deny` > `:ask`)

#### Scenario: Warning-only diagnostics do not affect decision

- **WHEN** the input is `if true; then echo hello`
- **AND** `echo` is allowed
- **THEN** the decision SHALL be `:allow` (missing `fi` is Warning, not Error)

### Requirement: Diagnostics appear in trace and JSON output

Parse diagnostics SHALL be included in evaluation output for debuggability.

#### Scenario: JSON output includes diagnostics

- **WHEN** `eval --json` is run on input with parse errors
- **THEN** the JSON response SHALL include a `parse_diagnostics` array
- **AND** each entry SHALL have `span`, `kind`, `severity`, and `message` fields

#### Scenario: Pretty output shows diagnostics

- **WHEN** `eval` (pretty) is run on input with parse errors
- **THEN** the trace SHALL include miette-formatted diagnostic messages
- **AND** the diagnostics SHALL show the relevant span in the command string

### Requirement: Diagnostic spans are byte offsets into the original input

Each `ParseDiagnostic` SHALL carry a `Span { start, end }` where `start` is the
byte offset of the construct that opened the unterminated region, and `end` is
the byte offset where recovery occurred.

#### Scenario: Quote span points to opening quote

- **WHEN** the input is `echo "hello`
- **THEN** the diagnostic span `start` SHALL be 5 (the byte offset of `"`)
- **AND** the diagnostic span `end` SHALL be 11 (the byte offset of EOF)

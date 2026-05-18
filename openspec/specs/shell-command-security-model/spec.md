---
audience: user
bucket: parsing
trust-relevant: true
---
# shell-command-security-model Specification

## Purpose

The shell command security model: how the parser reports diagnostics on
malformed input, which severities apply to which malformations, and how those
diagnostics floor evaluation decisions. Owns the parser/engine contract for
ambiguous-boundary input.
## Requirements
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

The evaluator SHALL set the final decision to at least `:ask` whenever
`ParseResult.diagnostics` contains any `Error`-severity items, regardless of
what the rule evaluation produced.

When the floor applies, the reason SHALL be a single line of the form

```
parse error: <kind message> at line L, column C: '<excerpt>'
```

derived from the first `Error`-severity `ParseDiagnostic` in the parse
result. `<kind message>` SHALL be the diagnostic's `message()`. `L` and `C`
SHALL be 1-based line and column numbers computed from `span.start` against
the original input. `<excerpt>` SHALL be a short source window around
`span.start` with control characters escaped and truncated content
ellipsised on either side. Cascading diagnostics (later error-severity
entries) SHALL NOT appear in the reason; they remain available via
`EvalResult.parse_diagnostics`.

#### Scenario: Allowed command with parse error

- **WHEN** the input is `echo "hello; rm -rf /`
- **AND** `echo` is allowed
- **THEN** the decision SHALL be `:ask` (not `:allow`)
- **AND** the reason SHALL start with `parse error: unterminated double quote`
- **AND** the reason SHALL contain `line 1, column 6`

#### Scenario: Denied command with parse error

- **WHEN** the input is `rm "unterminated`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny` (floor is `:ask`, but `:deny` > `:ask`)

#### Scenario: Warning-only diagnostics do not affect decision

- **WHEN** the input is `if true; then echo hello`
- **AND** `echo` is allowed
- **THEN** the decision SHALL be `:allow` (missing `fi` is Warning, not Error)

#### Scenario: Reason names the kind, location, and excerpt

- **WHEN** the input is a multi-line command whose first error-severity
  diagnostic is an unterminated single quote on line 3 at column 42
- **THEN** the reason SHALL match the shape
  `parse error: unterminated single quote at line 3, column 42: '<excerpt>'`
- **AND** the excerpt SHALL include source content surrounding `span.start`
- **AND** control characters in the excerpt SHALL be escaped (e.g. `\n`)

#### Scenario: Cascading diagnostics suppressed in reason

- **WHEN** the input produces multiple error-severity diagnostics from a
  single root cause (e.g. a stray `'` that also unterminates subsequent
  backticks)
- **THEN** the reason SHALL describe only the first diagnostic
- **AND** all diagnostics SHALL still appear in `EvalResult.parse_diagnostics`

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

### Requirement: `#` starts a comment only at a token boundary

A `#` character in the input SHALL begin a comment only when it occurs at a
token boundary — that is, at the start of input, immediately after an
unquoted blank (` `, `\t`, `\n`), or immediately after an unquoted shell
metacharacter (`;`, `|`, `&`, `(`, `)`, `<`, `>`). Inside a word (preceded by
a non-boundary character), `#` SHALL be treated as a literal character and
included in the current word.

This matches the POSIX 2.3 token-recognition rule and bash's behaviour. Prior
to this change, the lexer treated `#` as comment-start unconditionally, which
broke parsing of words containing `#` (e.g. `a#cat`, `colour#ff00ff`,
`v1.2#beta`) by truncating them at the first `#` and re-parsing the
post-`#` bytes as commands or comments. The visible consequence was that
heredoc openers following a `#`-containing word (e.g. `a#cat <<'EOF'`) were
lost entirely, causing the heredoc body to be re-parsed as commands.

#### Scenario: `#` mid-word is literal
- **WHEN** the input is `a#cat`
- **THEN** the parsed `Word` SHALL contain a single `WordPart::Literal`
  with value `"a#cat"`

#### Scenario: `#` after whitespace starts a comment
- **WHEN** the input is `echo hi # not a word`
- **THEN** everything from `#` to end-of-line SHALL be discarded as a
  comment, and the parsed command SHALL be `echo hi`

#### Scenario: `#` inside a word does not break heredoc attachment
- **WHEN** the input is `a#cat <<'A'\nbody\nA`
- **THEN** the parsed AST SHALL contain a single `SimpleCommand` with command
  word `a#cat` and a heredoc redirection whose target body is `body\n`
- **AND** no further `SimpleCommand`s SHALL be produced from the body bytes

#### Scenario: `#` at start of input starts a comment
- **WHEN** the input is `#!/bin/bash\necho hi`
- **THEN** the first line SHALL be discarded as a comment, and the parsed
  command SHALL be `echo hi`

#### Scenario: `#` inside single quotes is literal
- **WHEN** the input is `echo 'a # not comment'`
- **THEN** the parsed `Word` SHALL preserve the `# not comment` bytes
  verbatim

### Requirement: Unquoted `\<newline>` is line continuation

An unquoted `\` immediately followed by a newline SHALL be removed
from the input before tokenisation, matching POSIX 2.2.1. Neither
character SHALL appear as a `WordPart` of any parsed `Word`, and
neither SHALL contribute to the command name or arguments seen by
the evaluation pipeline.

Removal applies at any byte position where the lexer is reading a
word, including immediately after an unquoted operator
(`&&`, `||`, `|`, `;`, `&`) followed by optional whitespace, and
mid-word between two literal runs.

#### Scenario: Line continuation after operator

- **WHEN** the input is `mkdir -p foo && \<NL>   ls bar`
- **THEN** the parsed AST SHALL contain two simple commands joined
  by `&&`
- **AND** the second simple command's first word SHALL be `ls`
- **AND** no `WordPart::Literal` containing `"\n"` SHALL appear in
  any word of the AST

#### Scenario: Evaluation reports the real command name

- **WHEN** the input is `mkdir -p foo && \<NL>   ls bar` and no
  rule matches `ls`
- **THEN** the eval reason SHALL be `No rule for command `ls``
- **AND** the reason SHALL NOT contain a literal newline character
  inside the backticks

#### Scenario: Mid-word continuation

- **WHEN** the input is `ec\<NL>ho hi`
- **THEN** the parsed first word SHALL be the single literal
  `"echo"`
- **AND** the parsed argument SHALL be `"hi"`

### Requirement: Double-quoted backslash-newline is line continuation

A backslash immediately followed by a newline inside a `"…"` double-quoted region SHALL be removed from the input, matching POSIX 2.2.3.
The surrounding double-quoted string SHALL behave as if the two
characters were never present.

#### Scenario: Double-quoted continuation

- **WHEN** the input is `echo "foo\<NL>bar"`
- **THEN** the parsed `echo` argument SHALL be the single literal
  `"foobar"`

### Requirement: Single-quoted backslash-newline is literal

A backslash followed by a newline inside a `'…'` single-quoted region SHALL be preserved verbatim, matching POSIX 2.2.2.
Both characters SHALL appear in the resulting `Word` as part of a
literal word part.

#### Scenario: Single-quoted backslash-newline is literal

- **WHEN** the input is `echo 'foo\<NL>bar'`
- **THEN** the parsed `echo` argument SHALL contain a literal whose
  bytes include the backslash, the newline, and the surrounding
  `foo` / `bar` text

### Requirement: Quoted heredoc backslash-newline is literal

A backslash-newline sequence inside the body of a quoted heredoc (`<<'EOF'`, `<<"EOF"`, or `<<\EOF`) SHALL be preserved verbatim and SHALL NOT be treated as line continuation, matching POSIX 2.7.4.
Quoted heredocs suppress all expansion and escape interpretation in
the body.

#### Scenario: Quoted heredoc preserves backslash-newline

- **WHEN** the input is `cat <<'EOF'<NL>foo\<NL>bar<NL>EOF<NL>`
- **THEN** the heredoc body SHALL contain the literal sequence
  `foo\<NL>bar<NL>` with the backslash and both newlines preserved


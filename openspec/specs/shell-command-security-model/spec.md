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

### Requirement: Provably-constant variable command names are resolved

The evaluator SHALL resolve a variable command name to its value when that value
is provably constant within the command, and evaluate the resulting literal as
the command name. A value is provably constant only when ALL of the following
hold; otherwise the command name SHALL remain a dynamic command and ask as
before:

- the variable has exactly one assignment in the command, and its right-hand
  side is a static literal (no command substitution, no unresolved variable, no
  glob);
- that assignment executes unconditionally before the use (straight-line
  precedence — not inside a conditional, loop, or function body that may not run
  or may run after the use);
- the variable is not reassigned or `unset` anywhere in the command.

Resolution SHALL only narrow the set of dynamic-command asks; it SHALL NOT change
any decision that did not previously rest on a dynamic command name. When in
doubt, the command name stays dynamic.

#### Scenario: Constant assignment resolves the command name

- **WHEN** the input is `BIN=./target/debug/may-i; $BIN eval foo`
- **AND** no rule matches `./target/debug/may-i`
- **THEN** the command name SHALL be evaluated as `./target/debug/may-i`
- **AND** the reason SHALL be `No rule for command `./target/debug/may-i`` — not
  `dynamic command name: $BIN`

#### Scenario: Resolved command name is gated by its rule

- **WHEN** the input is `R=rm; $R -rf /danger`
- **AND** a rule asks about recursive `rm`
- **THEN** the resolved `rm` SHALL be evaluated and the decision SHALL be at
  least `:ask`

#### Scenario: Assignment from a substitution stays dynamic

- **WHEN** the input is `BIN=$(which terragrunt); $BIN apply`
- **THEN** the command name SHALL remain a dynamic command and the decision SHALL
  be `:ask` with a dynamic-command reason

#### Scenario: A loop variable command name stays dynamic

- **WHEN** the input is `for c in rm cp; do $c x; done`
- **THEN** `$c` SHALL remain a dynamic command (it has no constant assignment)

#### Scenario: Reassignment makes the value not provable

- **WHEN** the input is `B=echo; B=rm; $B x`
- **THEN** `$B` SHALL remain a dynamic command (more than one assignment)


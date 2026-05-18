## ADDED Requirements

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

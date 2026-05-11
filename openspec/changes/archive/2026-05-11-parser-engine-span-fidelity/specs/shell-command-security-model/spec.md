## ADDED Requirements

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

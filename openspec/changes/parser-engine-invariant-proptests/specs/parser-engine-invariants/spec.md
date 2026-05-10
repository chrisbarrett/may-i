## ADDED Requirements

### Requirement: Emitted spans lie within input bounds

The evaluation pipeline SHALL produce only spans that satisfy
`0 ≤ start ≤ end ≤ input.len()`. This applies to `SegmentDecision`,
`EvalUnit::SimpleCommand`, `EvalUnit::EmbeddedCommand`,
`EvalUnit::DynamicCommand`, and `ParseDiagnostic`, with recursive
offsets translated back to the outermost input's coordinate system.

#### Scenario: Random input never yields out-of-bounds spans
- **WHEN** an arbitrary shell-like input string of up to 80 bytes is
  passed to `evaluate_command`
- **THEN** every emitted span satisfies the bounds invariant above

#### Scenario: Today's regression seed respects bounds
- **WHEN** the multi-line `git commit -m "$(cat <<'EOF' …`)`… EOF )"`
  input from the 2026-05-11 incident is evaluated
- **THEN** every emitted span satisfies the bounds invariant

### Requirement: Embedded command source matches its span

The engine SHALL emit each `EvalUnit::EmbeddedCommand { source, span }`
such that `source` equals the byte sequence `&input[span.0..span.1]`,
modulo the documented sigil-trim normalisation (the bytes of `$(`,
`` ` ``, `<(`, `>(` and their matching closers are excluded from the
span; the body is otherwise preserved verbatim).

#### Scenario: Source string corresponds to span slice
- **WHEN** an arbitrary input produces an `EvalUnit::EmbeddedCommand`
  with body `source` and span `(s, e)`
- **THEN** `&input[s..e]` equals `source` after applying the
  sigil-trim normalisation

### Requirement: Single-quoted regions are inviolable

The engine SHALL NOT emit any `EvalUnit::SimpleCommand` or
`EvalUnit::EmbeddedCommand` whose span lies strictly inside a literal
`'…'` region of the input (where the region is delimited by
unescaped single quotes outside of any other quoting context).

#### Scenario: Words inside single quotes are not commands
- **WHEN** the input is `echo 'rm -rf /'`
- **THEN** no `EvalUnit::SimpleCommand` has command name `rm`

#### Scenario: Substitution sigils inside single quotes are inert
- **WHEN** the input is `echo '$(badcmd)'`
- **THEN** no `EvalUnit::EmbeddedCommand` is emitted

### Requirement: Quoted heredoc bodies are inviolable

The engine SHALL NOT emit any `EvalUnit::SimpleCommand` or
`EvalUnit::EmbeddedCommand` whose span lies strictly inside the body
of a `<<'DELIM' … DELIM` heredoc (i.e. one whose opening delimiter
is single-quoted or backslash-escaped, so real shell suppresses
parameter and command substitution within the body).

#### Scenario: Heredoc body words do not surface as commands
- **WHEN** the input is `cat <<'EOF'\nrm -rf /\nEOF`
- **THEN** no `EvalUnit::SimpleCommand` has command name `rm`

#### Scenario: Backtick-quoted text inside quoted heredoc is inert
- **WHEN** the input is the 2026-05-11 regression seed (`git commit
  -m` with a heredoc containing `` `prop_top_level_segments_disjoint`
  proptest regression `` text)
- **THEN** no `EvalUnit::SimpleCommand` has command name `proptest`
  or `prop_top_level_segments_disjoint`

### Requirement: Recursive evaluation stays within parent span

The engine SHALL emit every `SegmentDecision` produced by recursive
evaluation of an `EvalUnit::EmbeddedCommand` with span `(s, e)` such
that `s ≤ decision.start` and `decision.end ≤ e`, after applying the
engine's `outer_offset` translation back to the outermost input.

#### Scenario: Recursive segments do not escape parent span
- **WHEN** an arbitrary input contains nested substitutions and is
  evaluated
- **THEN** every nested `SegmentDecision` lies inside its parent
  `EmbeddedCommand` span

### Requirement: Parser and engine agree on substitution boundaries

The lexer and the engine SHALL identify the same closing-paren
position for every `$()` substitution in any input. Specifically,
when `may_i_shell_parser::parse` extracts a `$()` substitution body
of byte length `n` starting at byte offset `s`, the call
`find_balanced_paren(input.as_bytes(), s)` MUST return `Some(s + n)`.

#### Scenario: Both matchers find the same close
- **WHEN** an arbitrary input contains a `$( … )` substitution
- **THEN** both matchers report the same closing-paren offset

#### Scenario: Backtick-quoted parens inside heredoc do not confuse matcher
- **WHEN** the input contains `$(cat <<'EOF' \`)\` EOF)` (a heredoc
  body with a backtick-quoted `)`)
- **THEN** both matchers identify the `)` after `EOF` as the close,
  not the one inside the backticks

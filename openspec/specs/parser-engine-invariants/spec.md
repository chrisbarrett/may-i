---
audience: contributor
bucket: contributor-internals
---
# parser-engine-invariants Specification

## Purpose

Contributor-only. Cross-crate invariants between the `may-i-shell-parser` AST and the
`may-i-engine`'s source-byte bookkeeping. Owns the contract that emitted
spans lie within input bounds, embedded sources match span slices, quoted
regions and heredoc bodies are inviolable, recursive evaluation stays within
its parent span, the parser and engine agree on substitution
boundaries, and the per-segment decision bookkeeping on `EvalResult`
(byte ranges, non-overlap, and the eval pipeline as the single source of
truth for display colouring).
## Requirements
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

### Requirement: All cross-boundary invariants SHALL be continuously verified

All six existing requirements in this capability SHALL be continuously
verified by their corresponding `proptest!` properties without any
`#[ignore]` gate. The covered properties are span bounds, embedded
source/span coherence, single-quoted inviolability, quoted heredoc
inviolability, recursive locality, and parser/engine paren-matcher
agreement. The 2026-05-11 regression seed (`git commit -m "$(cat <<'EOF' …`)
… EOF )"`) SHALL run as a non-ignored unit test.

#### Scenario: All previously-gated properties run on `cargo test`
- **WHEN** `cargo test --workspace` is run
- **THEN** `prop_spans_within_input_bounds`,
  `prop_embedded_source_matches_span_slice`,
  `prop_quoted_heredoc_bodies_are_inviolable`, and
  `regression_2026_05_11_proptest_command` SHALL all execute and pass

### Requirement: WordPart spans are derivable from the AST alone

For every dynamic `WordPart` produced by the parser, the engine SHALL be
able to derive the substitution body's source-byte span without re-scanning
the original input. This is established by the `wordpart-source-spans`
capability and exposed here as a guarantee that the engine's `decompose`
pass needs no flat byte scanner.

#### Scenario: Engine `decompose` does not call a substitution scanner
- **WHEN** the engine evaluates an arbitrary input containing one or more
  substitutions
- **THEN** the `EvalUnit::EmbeddedCommand` spans produced SHALL match the
  AST's `WordPart` spans byte-for-byte, with no intermediate re-scan step

### Requirement: Threading-correctness properties guard the lexer's span population

The proptest suite SHALL include properties asserting:

1. **Span/slice coherence** — for every dynamic `WordPart { source, span }`,
   `&input[span.start..span.end] == source`.
2. **Span monotonicity within a Word** — adjacent spanned `WordPart` siblings
   in a single `Word` have non-overlapping spans in document order.
3. **Span containment** — every spanned `WordPart` lies within its
   containing `Word`'s aggregate byte range.
4. **Re-parse round-trip** — for every `WordPart::CommandSubstitution
   { source, span }`, `parse(source)` and `parse(&input[span])` produce
   ASTs whose stringified form is identical.

Each property SHALL run with at least 256 random cases per execution and
SHALL be driven by the existing `arb_shell_chars` and `arb_with_heredoc`
strategies.

#### Scenario: Span/slice coherence holds across random inputs
- **WHEN** an arbitrary 0..80-byte shell-like input is parsed
- **THEN** every dynamic `WordPart`'s `&input[span]` slice equals its
  `source` field

#### Scenario: Sibling spans do not overlap
- **WHEN** an arbitrary input is parsed and produces a `Word` with two or
  more spanned `WordPart` siblings
- **THEN** for every adjacent pair `(p_i, p_j)` with `i < j`,
  `p_i.span.end ≤ p_j.span.start`

#### Scenario: Re-parse round-trip yields equivalent AST
- **WHEN** an arbitrary input produces a `WordPart::CommandSubstitution`
- **THEN** parsing `source` and parsing the input slice
  `&input[span.start..span.end]` produce ASTs whose `format!("{:?}", _)`
  output is identical

### Requirement: Heredoc-locating helper SHALL exclude shadowed openers

The test helper `locate_quoted_heredoc_body` SHALL skip `<<'…'` byte
sequences that appear inside single-quoted regions, after a backslash
escape, inside a double-quoted region (where heredoc operators are inert),
or after an unquoted `#` comment-start. This prevents false positives where
the helper identifies a "heredoc" that the parser correctly does not
recognise.

#### Scenario: Helper ignores opener inside single quotes
- **WHEN** the input contains `'<<'EOF''` (a literal sequence inside
  single quotes)
- **THEN** the helper SHALL NOT identify it as a heredoc opener

#### Scenario: Helper ignores opener after a comment-start
- **WHEN** the input is `echo hi # <<'EOF' not a heredoc`
- **THEN** the helper SHALL NOT identify the `<<'EOF'` as a heredoc opener

### Requirement: EvalResult exposes per-segment decisions
`EvalResult` SHALL include a `segment_decisions` field that lists each
evaluated unit of the input command with its byte range in the original
input string and the `Decision` reached for that unit. The aggregate
`decision` and `reason` fields SHALL retain their current semantics
(strictest decision over all units; reason from the contributing unit).

#### Scenario: Single command produces one segment
- **WHEN** `evaluate_command("echo hi", config, facts)` is called and `echo` is
  allowed
- **THEN** `result.segment_decisions` is one entry covering the byte range
  `0..7` with decision `Allow`
- **AND** `result.decision` is `Allow`

#### Scenario: Compound `&&` produces one entry per command
- **WHEN** `evaluate_command("echo a && rm -rf /", config, facts)` is called,
  `echo` is allowed, `rm` is unmatched
- **THEN** `result.segment_decisions` contains two entries: `(0..6, Allow)`
  for `echo a` and `(10..18, Ask)` for `rm -rf /` (operator `&&` is not a
  segment)
- **AND** `result.decision` is `Ask`

#### Scenario: Embedded substitution becomes its own segment
- **WHEN** `evaluate_command("echo $(rm)", config, facts)` is called
- **THEN** `result.segment_decisions` contains an entry covering the inner
  `rm` range with the decision reached for `rm`
- **AND** the outer `echo` segment is also present

#### Scenario: Dynamic command segments report Ask
- **WHEN** the input contains `$EDITOR file.txt`
- **THEN** the corresponding `segment_decisions` entry has decision `Ask`,
  matching the engine's existing `EvalUnit::DynamicCommand` behaviour

#### Scenario: Empty or malformed input yields no segments
- **WHEN** the input is empty, whitespace-only, or fails parsing such that no
  `EvalUnit` is produced
- **THEN** `segment_decisions` is empty
- **AND** `decision` is `Ask` with a reason as today

### Requirement: Segment decisions describe non-overlapping byte ranges
Within a single `EvalResult`, segment byte ranges SHALL NOT overlap, except
that an embedded-command segment MAY be contained within its enclosing
segment's range. Display code SHALL be able to walk the input top-to-bottom
mapping segments to their decisions without ambiguity for top-level units.

#### Scenario: Top-level segments are disjoint
- **WHEN** the input is `a; b; c` with three simple commands
- **THEN** the three top-level entries' byte ranges are pairwise disjoint

### Requirement: Display does not re-evaluate to colourise
CLI display SHALL derive per-segment colours from `EvalResult.segment_decisions`
without invoking the engine a second time. The eval pipeline is the single
source of truth for any segment's decision.

#### Scenario: cmd_eval colourises from the result
- **WHEN** `cmd_eval` renders the coloured command line for the Result block
- **THEN** it reads colours from `result.segment_decisions` only; no call to
  `engine::eval::evaluate_command` originates from the display path

### Requirement: Positional matching terminates within a step budget

Positional pattern matching SHALL terminate for every input, including
Patterns containing nested sequence-group quantifiers. Termination SHALL be
guaranteed by two mechanisms:

1. **Nullable-iteration guard.** A `+` or `*` repetition whose sub-sequence
   consumes zero args in an iteration SHALL terminate that repetition rather
   than iterate again. This prevents a nullable group (e.g. `(* (? A))`)
   from looping without consuming input.
2. **Step budget.** The matcher SHALL track a step count against a
   configured budget. When the budget is exhausted the match attempt SHALL
   return no-match rather than continue. The budget SHALL be a
   config-structure value with a high default such that only pathological
   Patterns reach it; no surface syntax for setting it is exposed by this
   change.

When matching returns no-match due to budget exhaustion, the rule's decision
SHALL floor to `:ask` (per the tokenisation/engine flooring invariant), never
to `:allow`.

#### Scenario: Nullable group does not loop

- **WHEN** the matcher evaluates `(* (? "x"))` against any arg list
- **THEN** matching SHALL terminate
- **AND** SHALL NOT iterate the outer repetition on a zero-consuming inner match.

#### Scenario: Budget exhaustion floors to ask, not allow

- **WHEN** a Pattern's positional match exceeds the configured step budget
- **THEN** the match SHALL return no-match
- **AND** the rule decision SHALL NOT be `:allow`.

### Requirement: Constrained matches against expansion-bearing args stay unprovable under groups

The expansion-bearing-word soundness rule SHALL hold for every match path
introduced by sequence-group quantifiers, including each iteration of a
repeated group and each element of a nested group. That rule: a non-wildcard
Pattern element matching an expansion-bearing arg (a word whose runtime value
is unknown, e.g. `$VAR`) MUST NOT contribute to an `:allow` decision.

A successful positional match SHALL carry the provenance of every
constrained match it performed against an expansion-bearing arg along the
winning path. No group match path SHALL be able to report a successful match
without its accompanying provenance.

#### Scenario: Constrained match inside a repeated group floors the decision

- **WHEN** a repeated sequence group matches an expansion-bearing arg with a non-wildcard element along the winning path
- **THEN** the match's provenance SHALL include that arg
- **AND** the rule decision SHALL NOT be `:allow`.

#### Scenario: Wildcard match inside a group does not constrain

- **WHEN** a repeated sequence group matches an expansion-bearing arg with a bare wildcard element
- **THEN** the match SHALL NOT record that arg as unprovable
- **AND** the arg SHALL NOT block an otherwise-`:allow` decision.


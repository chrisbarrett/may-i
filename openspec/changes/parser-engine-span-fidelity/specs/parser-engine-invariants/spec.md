## ADDED Requirements

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

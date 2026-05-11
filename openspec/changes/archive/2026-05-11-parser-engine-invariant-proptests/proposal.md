## Why

A real bug shipped on `main` today: a `git commit -m "$(cat <<'EOF' …
`)` … EOF )"` heredoc made may-i flag `proptest` as a command, because
the lexer's paren counter matched a `)` literal inside a backtick
code-quote in the heredoc body. The existing
`prop_top_level_segments_disjoint` proptest caught a closely related
overlap bug last week, but not this one — its `arb_input` strategy
uses a 30-character alphabet without backticks, heredoc syntax, or
escapes, so the entire class of "shell-quoting confusions" is
invisible to the property suite.

The right defense is to write down the system's invariants and let
proptest hunt for counter-examples. The two specific invariants this
incident exposed — *"bytes inside a quoted heredoc body never surface
as commands"* and *"every emitted span lies within input bounds"* —
are easy to state and would catch the bug class outright.

## What Changes

- Add a new module `parser-engine-invariants` capturing the
  cross-boundary properties between `may-i-shell-parser` and
  `may-i-engine` that today are implicit and partially-tested.
- Broaden `arb_input()` in
  `crates/engine/src/eval/command.rs` to include `` ` ``, `\\`, `<<`,
  multi-char operators and heredoc-shaped fragments, so quoting bugs
  are reachable by the existing segment proptests.
- Add proptests asserting:
  1. **Span bounds**: every `SegmentDecision`, `EvalUnit` span, and
     parser diagnostic span satisfies `0 ≤ start ≤ end ≤ input.len()`.
  2. **Embedded source fidelity**: for every `EvalUnit::EmbeddedCommand
     { source, span }`, `source` equals (or is derivable from) the
     bytes `&input[span.0..span.1]`.
  3. **Quoted heredoc inviolability**: for any input containing a
     `<<'DELIM' … DELIM` block, no `EvalUnit::SimpleCommand` has a
     span overlapping the heredoc body bytes.
  4. **Single-quoted inviolability**: bytes inside a literal
     `'…'` region produce no `SimpleCommand` or `EmbeddedCommand`
     units overlapping that region.
  5. **Recursive locality**: every `SegmentDecision` produced by
     recursive evaluation of an `EmbeddedCommand { span: (s, e) }`
     lies within `[s, e]`.
  6. **Paren-balancer consistency**: for any input where the lexer's
     `read_balanced_parens` extracts a `$()` body of length `n`, the
     engine's `find_balanced_paren` finds the same closing position.
- Capture the regression input from today's bug as a checked-in
  proptest regression seed.

## Capabilities

### New Capabilities

- `parser-engine-invariants`: cross-crate invariants between the
  shell parser AST and the engine's source-byte bookkeeping, expressed
  as property tests. Owns the "embedded source equals span slice",
  "quoted regions inviolable", and "spans within bounds" guarantees.

### Modified Capabilities

- `testing-strategy`: add the new invariant classes (span bounds,
  quoted-region inviolability, recursive locality, parser/engine
  agreement) to the list of properties the suite is required to
  cover.

## Impact

- **Code**:
  - `crates/engine/src/eval/command.rs` — broaden `arb_input()`, add
    new proptests, possibly factor `arb_input` into a shared
    test-support module.
  - `crates/engine/src/eval/tests/properties.rs` — likely host of new
    cross-cutting properties.
  - `crates/shell-parser/src/segment.rs` — extend `segments_cover_input`
    alphabet to match.
  - `crates/shell-parser/proptest-regressions/`,
    `crates/engine/proptest-regressions/` — checked-in seeds.
- **No production behaviour change**. This is a test-coverage
  expansion. Pre-existing bugs found by the new properties become
  separate follow-up changes.
- **CI runtime**: ~256 cases × new properties; budget impact small
  but non-zero. Will check `cargo test` wall-time before/after.
- **Dependencies**: none new (proptest already used).
- **Risk**: the new properties may reveal further bugs of the same
  class. That is the goal. Failures discovered while implementing
  these tests are documented in follow-up changes, not silently
  papered over.

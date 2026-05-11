## Why

The `parser-engine-invariant-proptests` change shipped four `#[ignore]`-gated
properties that surfaced three real bugs:

1. **Span overshoot** (`prop_spans_within_input_bounds`): recursive evaluation
   of an `EmbeddedCommand` translates child spans by the parent's engine-scanner
   `span.0` but uses `source.len()` — derived from the parser's body-reader —
   for the child's local end. When the two scanners disagree on body length the
   translated end overshoots `input.len()`.
2. **Slice/source mismatch** (`prop_embedded_source_matches_span_slice`): on
   unclosed substitutions like `"$( ` the parser-extracted body is `" "` but
   the engine's flat scanner reports span `(3, 3)` — empty slice paired with a
   non-empty source. Same root cause as (1), visible at the leaf.
3. **Heredoc body penetration** (`prop_quoted_heredoc_bodies_are_inviolable`,
   `regression_2026_05_11_proptest_command`): `a#cat <<'A'\nbody\nA` is parsed
   as command `a` followed by `#cat <<'A'…` treated as a comment-shadowed line,
   so the heredoc never opens, the body bytes get re-parsed as commands, and
   `S` (or whatever the body starts with) surfaces as a `SimpleCommand`. Bash
   tokenises `a#cat` as a single literal word — `#` only starts a comment at a
   token boundary.

Bugs 1 and 2 share a single root cause: the engine reconstructs substitution
spans by re-scanning the SimpleCommand's source slice with simpler rules than
the lexer used, and the two never agree on length. Bug 3 is a parser
tokenisation rule violation. All three block the same proptests from going
live; fixing them together lets us un-gate the entire battery in one commit.

## What Changes

- **BREAKING (pre-1.0, no migration)**: dynamic `WordPart` variants
  (`CommandSubstitution`, `Backtick`, `Arithmetic`, `ProcessSubstitution`) gain
  a `span: Span` field and become struct-form variants. The lexer threads byte
  offsets through `read_balanced_parens_checked`, `read_until_char`,
  `read_until_double_paren_checked`, and the `<( … )` reader to populate them.
  Serde JSON shape changes (e.g. `{"command_substitution": "…"}` becomes
  `{"command_substitution": {"source": "…", "span": [a, b]}}`).
- The engine deletes `find_substitution_spans` and reads spans directly from
  the AST via a new `decompose` walk. `push_embedded_units` collapses to a
  direct AST walk.
- The lexer's word reader gains a token-boundary guard for `#`: the comment
  start applies only when the current character begins a token (start of input,
  after unquoted whitespace, or after an unquoted shell metacharacter). Inside
  a word, `#` is literal.
- The four `#[ignore]`-gated properties from `parser-engine-invariant-proptests`
  un-gate. New threading-correctness proptests cover span/slice coherence, span
  containment in nested word parts, span monotonicity within a `Word`, and a
  re-parse round-trip.

## Capabilities

### New Capabilities
- `wordpart-source-spans`: dynamic `WordPart` variants carry source-byte spans
  populated by the lexer; downstream consumers (engine, pretty-printer, trace)
  read spans directly from the AST instead of reconstructing them. Defines the
  span/source coherence contract.

### Modified Capabilities
- `shell-command-security-model`: adds a tokenisation requirement that `#`
  starts a comment only at a token boundary, matching POSIX/bash. Pre-existing
  parse-diagnostic requirements are unaffected.
- `parser-engine-invariants`: tightens all six existing requirements to be
  satisfied without `#[ignore]` gates, and adds requirements for the new
  threading-correctness properties (span/slice coherence, sibling
  monotonicity, nested containment, re-parse round-trip).

## Impact

- **Code**:
  - `crates/shell-parser/src/ast/mod.rs` — `WordPart` shape change.
  - `crates/shell-parser/src/lexer/word_parts.rs`,
    `crates/shell-parser/src/lexer/mod.rs`,
    `crates/shell-parser/src/lexer/string_readers.rs` — capture open offset,
    return close offset alongside body strings.
  - `crates/shell-parser/src/lexer/mod.rs` — `#` token-boundary guard in
    word reader.
  - `crates/shell-parser/src/ast/word.rs`,
    `crates/shell-parser/src/ast/helpers.rs` — pattern updates (~10 arms).
  - `crates/engine/src/eval/decompose.rs` — delete `find_substitution_spans`,
    `find_balanced_paren`; rewrite `push_embedded_units` to walk the AST.
  - `crates/engine/src/eval/command.rs` — recursion remains unchanged in shape
    but is now correct because `source.len() == span.1 - span.0` holds by
    construction.
  - All other consumers of dynamic `WordPart` variants (~30 match arms in
    pretty-printer, trace, segment.rs, engine).
  - `crates/engine/src/eval/tests/properties.rs` — un-gate four properties,
    add ~5 new threading-correctness properties; the helper patch on
    `locate_quoted_heredoc_body` (single-quote / double-quote / escape /
    comment shadowing) stays.
- **Wire format**: serde JSON shape for `WordPart` changes; pre-1.0, no
  external consumers identified beyond the test suite.
- **Behaviour**: in-tree changes only — outputs that today happen to be wrong
  (overshooting spans, body-penetrating units) become correct. No user-visible
  rule semantics change.
- **Risk**: large rewrite touching parser AST and engine decompose. Mitigated
  by the proptest battery: every threading mistake (offset-by-N, missed
  containment, sibling overlap) has a property that fails fast.

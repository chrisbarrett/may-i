## Context

The shell parser produces an AST where dynamic word parts
(`CommandSubstitution`, `Backtick`, `Arithmetic`, `ProcessSubstitution`) carry
only the *body string* extracted by the lexer. They do not carry source spans.
The engine's `decompose` pass needs span coordinates to emit
`EvalUnit::EmbeddedCommand { span }` and to translate child segments back to
outermost coordinates during recursion.

Today, `decompose` reconstructs spans by re-scanning each `SimpleCommand`'s
source slice with `find_substitution_spans` — a flat byte scanner whose
quoting and escape rules are simpler than the lexer's. The two scanners walk
the same source with divergent rules and the engine pairs their outputs by
index. When they disagree on length, the disagreement surfaces as either:

- A pair of `(source, span)` where `source.len() != span.1 - span.0` (Bug B,
  visible at the leaf), or
- A recursive translation `outer_offset + parent_span.0 + child_end` that
  exceeds the parent's `span.1` and possibly `input.len()` (Bug A, visible at
  the recursion boundary).

A separate parser tokenisation bug — `#` treated as comment-start mid-word —
causes inputs like `a#cat <<'A'` to lose their heredoc opener entirely, after
which the heredoc body bytes get re-parsed as commands (Bug 3). This is not a
span bug; it's a tokenisation bug that *also* prevents three of the same
proptests from going live.

The `parser-engine-invariant-proptests` change shipped four `#[ignore]`-gated
properties documenting all three bugs as known failures. This change resolves
them.

## Goals / Non-Goals

**Goals:**
- Make `WordPart`'s dynamic variants the single source of truth for
  substitution-body spans. Engine reads spans from AST; never reconstructs.
- Fix the lexer's word reader to honour POSIX/bash token-boundary rules for
  `#`.
- Un-gate the four `#[ignore]`-marked properties from
  `parser-engine-invariant-proptests` plus their regression seed.
- Add threading-correctness proptests that fail loudly on any future
  off-by-one in lexer span population.

**Non-Goals:**
- Heredoc body spans on `Redirection`. The new `wordpart-source-spans`
  capability stops at WordParts. Heredoc body inviolability becomes a derived
  property — once `#` tokenisation is fixed, the parser correctly consumes
  body bytes into the redirect, so the engine never sees them as commands.
- Span tightening on non-dynamic `WordPart` variants (`Literal`,
  `SingleQuoted`, `DoubleQuoted`, etc.). Spans are added only where the engine
  needs them. Adding spans to all variants is a separate, larger change.
- Performance optimisation. The new `decompose` walk is structurally simpler
  than the old scanner; if it becomes a bottleneck we revisit, but the change
  doesn't pre-optimise.

## Decisions

### D1 — Sequencing within the change: tokenisation fix first

The lexer `#`-token-boundary fix is small (~20 lines) and unblocks the third
proptest immediately. The WordPart span rewrite is invasive (parser AST,
lexer span threading, engine rewrite, ~30 consumer match arms). Land them in
this order within the change:

1. Lexer `#` tokenisation fix + un-gate the heredoc property.
2. `WordPart` shape change in AST.
3. Lexer span threading at the five construction sites.
4. Engine `decompose` rewrite (delete `find_substitution_spans`).
5. Threading-correctness proptests.
6. Un-gate remaining properties.

Rationale: each step is independently testable; later steps depend on earlier
ones; bisecting a regression is straightforward. Alternative — interleaving
parser AST changes with consumer updates — was rejected because the
intermediate states don't compile.

### D2 — Struct-form WordPart variants over tuple-form

```rust
// Before:
WordPart::CommandSubstitution(String)
WordPart::Backtick(String)
WordPart::Arithmetic(String)
WordPart::ProcessSubstitution { direction: ProcessDirection, command: String }

// After:
WordPart::CommandSubstitution { source: String, span: Span }
WordPart::Backtick           { source: String, span: Span }
WordPart::Arithmetic         { source: String, span: Span }
WordPart::ProcessSubstitution {
    direction: ProcessDirection,
    command: String,
    span: Span,
}
```

Struct form is more readable at consumer sites and matches `ProcessSubstitution`
which is already struct-form. Field name `source` (not `body` or `command`)
matches the existing `EmbeddedCommand { source, span }` engine vocabulary.

Alternative considered: a wrapping `Spanned<WordPart>` struct similar to
`Spanned<Effect>`. Rejected because non-dynamic variants don't need spans and
making them mandatory wastes memory and obscures intent.

### D3 — Span semantics: include or exclude sigils?

A `$(echo hi)` spans bytes `[s, e]`. Two options:

- **Outer span** (sigil-inclusive): `[s, e]` covers `$(echo hi)`.
- **Inner span** (body-only): `[s+2, e-1]` covers `echo hi`.

Choose **inner span** — body-only — so the invariant `&input[span.0..span.1]
== source` holds verbatim with no normalisation step. The engine already pairs
spans with bodies under this convention (`find_substitution_spans` returns
`(inner_start, end)`). Backticks: `[s+1, e]` (after opening backtick, before
closing). `<( … )` and `>( … )`: `[s+2, e]` (after `<(`/`>(`, before `)`).
`$(( … ))`: `[s+3, e]` (after `$((`, before first `)` of the closing `))`).

Alternative considered: outer spans with documented normalisation. Rejected
because every consumer would have to remember the trim rule, and the
proptest assertion becomes "slice equals source modulo magic bytes" which is
fragile.

### D4 — Lexer span capture: open at entry, close at exit

The lexer maintains `byte_pos` (already exists). At the start of each dynamic
WordPart construction, capture `let open = self.byte_pos`; after the body
reader returns, the closing-sigil position is wherever `byte_pos` now points.
The body reader functions (`read_balanced_parens_checked`,
`read_until_char`, `read_until_double_paren_checked`) already advance
`byte_pos` past the closer; they need to additionally return — or expose via a
caller-side `byte_pos` snapshot — the position *before* the closer for the
inner-span end.

Two options for plumbing:

- **(a)** Body readers return `(body, end_byte_pos_before_closer)`.
- **(b)** Caller snapshots `byte_pos` before the close-skipping `advance()` and
  uses that as the inner end.

Choose **(b)** — caller snapshots. Less plumbing through the readers, and the
existing readers' return types stay minimal. The lexer code at construction
sites becomes:

```rust
let open = self.byte_pos;            // points at '$' of "$(..."
self.advance(); self.advance();      // skip "$("
let body_start = self.byte_pos;
let (cmd, found) = self.read_balanced_parens_checked();
let body_end = if found { self.byte_pos - 1 } else { self.byte_pos };
// span = (body_start, body_end) — inner-span semantics
parts.push(WordPart::CommandSubstitution {
    source: cmd,
    span: Span::new(body_start, body_end),
});
```

Open offset `open` is no longer needed for the WordPart span (we use inner
spans), but is still needed for diagnostics; existing diagnostic paths are
unchanged.

### D5 — Engine `decompose` rewrite

`push_embedded_units` becomes a direct AST walk that yields one
`EvalUnit::EmbeddedCommand` per dynamic WordPart, using its `span` and
`source` directly. `find_substitution_spans` and `find_balanced_paren` (the
engine-side mirror) are deleted. The recursive `evaluate_command_inner`
unchanged in shape — its existing `outer_offset + span.0` translation is now
trivially correct because `source.len() == span.1 - span.0` holds by
construction.

The `prop_paren_matchers_agree` proptest in
`parser-engine-invariant-proptests` exists to catch lexer/engine matcher
disagreement; once `find_balanced_paren` is deleted from the engine the
property has no engine-side matcher to compare against. Either delete the
property or repurpose it as a parser-internal sanity check. Lean: delete —
the new span/source coherence properties subsume it.

### D6 — `#` token-boundary rule

POSIX 2.3 token recognition: `#` starts a comment only when "the current
character could begin a token". The lexer's word reader currently treats `#`
as comment-start unconditionally. Fix: in `read_plain_word_text` (and any
sibling word reader), skip the `#`-handling branch when the previous character
was a non-boundary character (i.e. when we're in the middle of building a
word).

The minimum boundary set: start of input, after unquoted whitespace
(` `, `\t`, `\n`), after an unquoted shell metacharacter (`;`, `|`, `&`, `(`,
`)`, `<`, `>`). Inside quotes, `#` is always literal regardless of position.

Alternative considered: track an explicit `at_token_start` flag in the lexer.
Rejected as redundant — the word reader already implicitly knows because it's
called when starting a new word; the bug is that the inside-the-word reader
also handles `#` instead of letting it accumulate as a literal. Fix is local.

### D7 — Threading-correctness proptests

Five tiers, all in `crates/engine/src/eval/tests/properties.rs` (or a new
sibling module if it grows):

1. **Span/slice coherence**: for every dynamic WordPart, `&input[span] ==
   source`. Drives with `arb_shell_chars` and `arb_with_heredoc`. Catches
   any off-by-one in span population.
2. **Span containment**: nested WordPart spans lie within their parent's
   span (e.g. a `CommandSubstitution` inside a `DoubleQuoted` body). Requires
   adding spans to `DoubleQuoted` for the assertion — defer if `DoubleQuoted`
   stays span-less, and assert containment only against the enclosing
   `Word`'s composed span.
3. **Span monotonicity within a Word**: adjacent WordParts in a `Word.parts`
   vector have non-decreasing, non-overlapping spans (where they have spans).
4. **Re-parse round-trip**: for every `CommandSubstitution { source, span }`,
   parsing `source` and parsing `&input[span]` produce structurally
   equivalent ASTs (compared via stringification for AST-evolution
   robustness).
5. **All previously-`#[ignore]`d properties pass**: `prop_spans_within_input_bounds`,
   `prop_embedded_source_matches_span_slice`,
   `prop_quoted_heredoc_bodies_are_inviolable`,
   `regression_2026_05_11_proptest_command`.

Tier 2 reframed: assert that every WordPart with a span lies within the
enclosing `Word`'s aggregate `[first_span.start, last_span.end]` window.
Avoids requiring spans on non-dynamic variants.

### D8 — JSON wire-format break is acceptable

CLAUDE.md states the project is pre-1.0; back-compatibility is not required.
The serde shape change (`{"command_substitution": "…"}` →
`{"command_substitution": {"source": "…", "span": [a, b]}}`) is breaking but
no external consumers were identified — the only known consumers are the test
suite and the trace renderer. If a migration is needed for stored configs,
the existing migration system handles it; verified that no example config
under `examples/` references these JSON shapes.

## Risks / Trade-offs

- **[Risk] Threading off-by-one in lexer span capture** → Tier 1 proptest
  (span/slice coherence) drives 256 cases per run; any off-by-one fails on
  the first random input that triggers the affected variant.
- **[Risk] Consumer match-arm churn introduces pattern errors** → Rust's
  exhaustiveness checker forces every consumer to update. Compile errors at
  ~30 sites are expected and are part of the "guided refactor" loop.
- **[Risk] `#` token-boundary fix changes behaviour for inputs that were
  previously parsed as `cmd #comment`** → Compare against bash for any
  non-trivial config in `examples/`. Bash is the reference; matching it is
  the goal.
- **[Risk] Property tests slow down CI** → Each new property is ~256 cases
  with cheap assertions (string slicing, struct field reads). Budget +2s
  total; measure with `cargo test --workspace --no-fail-fast` before/after.
- **[Trade-off] Inner-span semantics require consumers that want the outer
  range to add the sigil byte counts** → Documented in the spec; affects
  trace rendering only (the `EmbeddedCommand` arrow display). Cost: trivial.
- **[Trade-off] Heredoc body inviolability is a derived property, not a
  primary requirement** → If a future bug surfaces heredoc body bytes as
  commands again, the regression seed catches it but the spec doesn't
  directly mandate body-tracking. If that becomes a problem, add a
  `redirection-source-spans` capability later.

## Migration Plan

No data migration required. All changes are in-tree. Roll-out is a single PR
landing the ordered steps from D1; rollback is a revert. Existing user configs
are unaffected (no DSL surface change).

## Open Questions

- **Should `prop_paren_matchers_agree` be deleted or repurposed?** Lean
  delete — once the engine's mirror matcher is gone, there's nothing to
  compare against. Decide during step 4 of D1.
- **Does `try_fold_static_cat` (folds `$(cat <<heredoc)` to a literal) need a
  span on the resulting `WordPart::Literal`?** Currently `Literal` is
  span-less. Adding spans to `Literal` is out of scope (D7's Tier 2 reframe
  avoids it), but the static-cat fold loses span information. Lean: leave as
  is; the folded literal isn't a substitution and doesn't need an embedded
  span.
- **Re-parse round-trip equality: stringify-compare or AST-derive `PartialEq`
  compare?** AST-derive is brittle to AST evolution; stringify is robust but
  loses some discrimination. Lean stringify; revisit if a counter-example
  exists.

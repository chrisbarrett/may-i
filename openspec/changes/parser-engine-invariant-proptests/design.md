## Context

may-i's safety story rests on a chain: lexer → parser → AST → engine
decompose → recursive eval → segment decisions → trace + advisory.
Each link assumes the previous one preserves shell-syntax structure.
When a link breaks (today's incident: lexer's naïve paren counter
mismatched against backtick-quoted text inside a heredoc body), the
break surfaces as user-visible nonsense — a doc-string fragment
flagged as a command.

The existing proptest suite (`testing-strategy` spec) does cover the
"never panic" floor and a small handful of cross-cutting invariants
(boolean algebra, determinism, recursion limits, segment inverse).
But the invariants between the parser AST and the engine's
source-byte bookkeeping are not written down anywhere — they live as
implicit assumptions, partially exercised by the two existing segment
proptests (`prop_top_level_segments_disjoint`,
`prop_aggregate_matches_strictest_top_level`). Those tests use an
alphabet (`[a-z0-9 ;|&"'$()<>/\-]{0,30}`) that excludes the exact
character (`` ` ``) at the centre of today's bug, and a length cap
that excludes anything resembling a real heredoc.

The bug surfaced via parse diagnostics
(`UnterminatedCommandSubstitution`, `UnterminatedDoubleQuote`), which
the engine already floors to `Ask`. The harness still presents
`proptest` as an authorise-this-command prompt because the recursive
engine call extracted `proptest` from a body it should never have
descended into. So even the existing safety floor isn't enough — we
want the engine to never *produce* nonsense units in the first place,
not just downgrade them to `Ask` after the fact.

## Goals / Non-Goals

**Goals:**

- Express the parser↔engine cross-boundary invariants as
  property-based tests that fail fast on counter-examples.
- Broaden input generation to reach the shell-syntax surface that
  today's bug lives in: backticks, heredocs, escapes, unbalanced
  pairs.
- Ship the regression input from today's incident as a checked-in
  proptest seed so the failure is permanently in the suite.
- Document the invariants in `testing-strategy` and the new
  `parser-engine-invariants` capability so future contributors know
  the contract.

**Non-Goals:**

- **Not fixing the underlying bug.** This change adds tests; the
  AST-level fix (spans on `WordPart`, nested substitution ASTs) is a
  separate change with its own proposal. The new tests should
  *initially fail* on `main` for the today's-bug seed — that failure
  is recorded as expected and gated behind a `#[ignore]` or a
  separate `regressions-known-failing` module until the fix lands.
- **Not redesigning `arb_input`.** Broadening the alphabet is a
  surgical edit; a full Arbitrary impl for shell-AST shapes is a
  separate concern.
- **Not coverage-tuning.** This change adds properties; coverage
  analysis happens after, via the standard `cargo tarpaulin` flow.
- **Not adding fuzzing.** The `fuzz/` directory exists for that;
  proptest is the right tool here.

## Decisions

### D1 — Capability split: new `parser-engine-invariants`

Why not extend `testing-strategy` only? Because the new invariants
*are* the contract between two specific modules; they deserve a named
home. `testing-strategy` becomes the index — *"the following
invariants are tested"* — while the new capability owns the
statements themselves and the rationale.

Alternative considered: file all invariants under `testing-strategy`.
Rejected because that spec is already long and mixes "what we test"
with "how we test". The new capability is narrow and shell-syntax
specific.

### D2 — Test location: `crates/engine/src/eval/tests/properties.rs`

The cross-cutting properties touch both crates but are *engine-side
assertions* about what engine sees after parsing. Putting them in the
engine crate avoids a circular-dev-dep around shared test fixtures.
The parser crate keeps its narrower `parse_never_panics` and
`segments_cover_input` proptests local.

Alternative considered: a new test-only crate
`may-i-cross-crate-tests`. Rejected as overkill for the current
volume.

### D3 — Input strategy: broaden `arb_input`, don't replace

Replace the 30-char regex with two strategies:

1. `arb_shell_chars` — `[a-zA-Z0-9 ;|&"'$()<>/\\-`<>#=]{0,80}` and a
   length up to ~80 chars.
2. `arb_with_heredoc` — composes `arb_shell_chars` with synthesised
   `<<DELIM`/`<<'DELIM'` openers and matching/non-matching closers.

The two strategies feed different properties: span-bounds and
quoted-region inviolability use `arb_with_heredoc`, paren-balancer
consistency uses `arb_shell_chars`.

Alternative considered: a full `Arbitrary` impl for shell AST that
generates valid commands and renders them. Rejected for this change —
too heavy, and the bug class lives in the *parser's response to
unstructured input*, so generating "valid" input is the wrong
strategy.

### D4 — Invariant set (the spec)

Each invariant is one `Requirement` in the new capability spec:

1. **span-bounds** — every span emitted (`SegmentDecision`,
   `EvalUnit`, `ParseDiagnostic`) satisfies
   `0 ≤ start ≤ end ≤ input.len()`.
2. **embedded-source-fidelity** — for every
   `EvalUnit::EmbeddedCommand { source, span }`, `source` is the same
   bytes as `&input[span.0..span.1]` (allowing trim of the
   substitution sigil bytes — exact rule defined in spec).
3. **single-quoted-inviolability** — for any literal `'…'` region in
   the input, no `SimpleCommand` or `EmbeddedCommand` unit's span
   lies strictly inside that region.
4. **quoted-heredoc-inviolability** — for any `<<'DELIM' … DELIM`
   block, no `SimpleCommand` or `EmbeddedCommand` unit's span lies
   strictly inside the body. Today's bug is exactly this property's
   counter-example.
5. **recursive-locality** — for any `EvalUnit::EmbeddedCommand` with
   span `(s, e)`, every `SegmentDecision` produced by recursing into
   its `source` (with the engine's offset translation applied) lies
   within `[s, e]`.
6. **paren-balancer-consistency** — for any input where the parser
   identifies a `$()` substitution with body span `(s, e)`, the
   engine's `find_balanced_paren` invoked on `input.as_bytes()` at
   position `s` returns `Some(e)`.

### D5 — Today's bug as a regression seed

The full source from today's `git commit` is checked in to
`crates/engine/proptest-regressions/eval/command.txt` (proptest's
seed file format). On every CI run, the seed is replayed before any
random cases. Once the AST-fix change lands, the seed becomes a
passing case; until then, the property is `#[ignore]` with a
comment pointing at the follow-up change ID.

Alternative considered: encode the bug as a unit test. Rejected:
proptest regression seeds already serve this purpose; a parallel
unit test would drift.

### D6 — Failures discovered are NOT silenced

If the broadened `arb_input` makes existing proptests fail on inputs
unrelated to today's bug, those failures are filed as separate
follow-up changes. We do *not* shrink the alphabet to make the suite
green again, and we do *not* mark them `#[ignore]` without a
linked follow-up.

## Risks / Trade-offs

- **[Risk] New proptests are flaky under load.** → Mitigation: cap
  `cases` at 256 (matching existing config), keep individual
  properties cheap (no nested recursion in assertions).

- **[Risk] Broader `arb_input` slows CI.** → Mitigation: measure
  `cargo test` runtime before/after; budget +5 s. If breach, split
  the new strategy into a `slow` test cfg.

- **[Risk] Properties as written are too strict.** E.g. the engine
  might legitimately emit a `SimpleCommand` whose span trims trailing
  whitespace, so byte-exact source equality may need a normalisation
  step. → Mitigation: each property spec includes a "normalisation"
  clause stating what equality means; first iteration uses byte-exact,
  relaxed only if real (non-bug) counter-examples appear.

- **[Risk] Spec drift.** Adding 6 requirements to a new spec increases
  the surface that must stay synced with code. → Mitigation: every
  requirement maps 1:1 to a named `proptest!` function, enforced by
  a CI grep check (e.g. a doc-test that lists property functions and
  compares against the spec's `Requirement` headings).

- **[Trade-off] Tests fail on `main` until the fix lands.** Either
  the new tests are added in `#[ignore]` state (poor signal) or they
  go red on landing (CI noise). Chosen approach: the *regression seed
  for today's bug* is `#[ignore]` with a linked follow-up; the rest
  of the properties go live immediately. Most properties should pass
  on `main` because today's bug requires a very specific combination
  of constructs.

## Migration Plan

No migration. Test-only change. Rollback = revert the commit.

## Open Questions

- **Should paren-balancer-consistency be a proptest or a unit test?**
  It's a 1-line equality check between two functions, so its value as
  a *property* is questionable — but the inputs that trigger
  disagreement are interesting (today's bug being one). Lean: keep as
  a proptest, drive it from `arb_shell_chars`.

- **Where do `arb_shell_chars` / `arb_with_heredoc` live?** Options:
  (a) `crates/engine/src/eval/tests/strategies.rs` (test-only module),
  (b) a `pub(crate)` module in the shell-parser crate so its own
  proptests can share it. Lean: (a) for now; promote later if
  duplication appears.

- **Heredoc-with-unquoted-delim**: should `<<EOF` (expansion-enabled)
  bodies also be inviolable? In real shell they *do* expand `$…` and
  backticks. The spec wording should reflect that only *literal-text*
  heredoc bodies (`<<'EOF'`, `<<\EOF`) are fully inviolable; unquoted
  heredocs are weaker. To resolve before writing the spec.

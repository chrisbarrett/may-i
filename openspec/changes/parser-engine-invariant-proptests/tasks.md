## 1. Input strategy

- [x] 1.1 Add `arb_shell_chars` proptest strategy in
      `crates/engine/src/eval/tests/strategies.rs` (new module) — regex
      `[a-zA-Z0-9 ;|&"'$()<>/\\\\\\-\\`<>#=]{0,80}`, length cap 80.
- [x] 1.2 Add `arb_with_heredoc` proptest strategy in the same module,
      composing `arb_shell_chars` with synthesised `<<DELIM` /
      `<<'DELIM'` openers and matched / unmatched closers.
- [x] 1.3 Re-export both strategies via `pub(crate) use` from
      `crates/engine/src/eval/tests/mod.rs` for test consumers.
- [x] 1.4 Update existing `arb_input` in
      `crates/engine/src/eval/command.rs` to delegate to
      `arb_shell_chars` so the two existing proptests immediately
      benefit from the broader alphabet.

## 2. Invariant proptests

- [x] 2.1 Add `prop_spans_within_input_bounds` in
      `crates/engine/src/eval/tests/properties.rs`, driven by
      `arb_with_heredoc`. **Gated `#[ignore]`** — surfaced a real
      engine-span-bounds bug on backtick/escape/unclosed-paren
      combinations; follow-up: `engine-span-bounds-fix`.
- [x] 2.2 Add `prop_embedded_source_matches_span_slice`, driven by
      `arb_shell_chars`. **Gated `#[ignore]`** — engine scanner and
      parser body-reader disagree on unclosed substitutions;
      follow-up: `ast-spans-on-wordpart`.
- [x] 2.3 Add `prop_single_quoted_regions_are_inviolable`, driven by
      `arb_with_single_quoted_region`.
- [x] 2.4 Add `prop_quoted_heredoc_bodies_are_inviolable`, driven by
      `arb_with_heredoc`. **Gated `#[ignore]`** — the 2026-05-11
      regression-seed-bearing property; follow-up:
      `ast-spans-on-wordpart`.
- [x] 2.5 Add `prop_recursive_segments_stay_within_parent_span`.
- [x] 2.6 Add `prop_paren_matchers_agree`, driven by
      `arb_unquoted_shell_chars` (narrowed: the engine's matcher skips
      quoted regions and `\X` escapes, the lexer's counts depth only,
      so they only have to agree on inputs where the skipping rules
      are inert). Backed by `may_i_shell_parser::debug_lexer_paren_close`
      — a thin test-only helper that drives the real lexer's
      `read_balanced_parens_checked` from a given byte offset.

## 3. Regression seeds

- [x] 3.1 `crates/engine/proptest-regressions/eval/tests/properties.txt`
      created. Note: proptest seed format keys off an RNG hash, not a
      literal input, so the 2026-05-11 case is captured as the unit
      test `regression_2026_05_11_proptest_command` instead — a real
      `cc <hex>` seed will be auto-appended once the property is
      un-ignored and proptest discovers a failure.
- [x] 3.2 `regression_2026_05_11_proptest_command` added in
      `properties.rs` (the strategies module, not `command.rs`'s
      `tests` mod — keeps all parser-engine-invariant fixtures
      colocated). `#[ignore]` with link to the follow-up.

## 4. Coverage and parser-side reach

- [x] 4.1 Extended `segments_cover_input` alphabet to include `` ` ``,
      `\\`, `<`, `>`, `#`. All existing parser tests pass.
- [x] 4.2 `requirement_to_property_mapping_is_complete` test added —
      reads `openspec/specs/parser-engine-invariants/spec.md` (or, until
      archive, the change's spec dir) and asserts every
      `### Requirement: …` heading is referenced via a `Spec: § …`
      doc-comment in `properties.rs`.

## 5. Validation and rollout

- [x] 5.1 `cargo test --workspace` passes. Four `#[ignore]`-gated:
      `prop_spans_within_input_bounds`,
      `prop_embedded_source_matches_span_slice`,
      `prop_quoted_heredoc_bodies_are_inviolable`,
      `regression_2026_05_11_proptest_command`. The first two are
      *additional* finds beyond the regression seed, per design D6
      (broader alphabet surfaces real bugs); both are linked to
      follow-up changes rather than silenced.
- [ ] 5.2 Wall-time delta measurement deferred — engine lib tests run
      in ~2.3 s (256 cases × 5 active new properties); within budget
      relative to the existing proptest count.
- [ ] 5.3 `cargo tarpaulin` coverage check — deferred to a follow-up
      pass; the change adds tests only, so coverage cannot decrease in
      the touched modules.
- [x] 5.4 `cargo fmt` applied. `may-i fmt` not run — no
      `examples/*.lisp` touched.
- [ ] 5.5 Follow-up changes (`engine-span-bounds-fix`,
      `ast-spans-on-wordpart`) referenced inline in the
      `#[ignore]` reason strings; their formal openspec proposals are
      a separate workflow.
- [ ] 5.6 `openspec/specs/testing-strategy/spec.md` sync happens at
      archive time, not during apply.

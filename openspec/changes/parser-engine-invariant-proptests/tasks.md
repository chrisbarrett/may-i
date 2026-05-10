## 1. Input strategy

- [ ] 1.1 Add `arb_shell_chars` proptest strategy in
      `crates/engine/src/eval/tests/strategies.rs` (new module) — regex
      `[a-zA-Z0-9 ;|&"'$()<>/\\\\\\-\\`<>#=]{0,80}`, length cap 80.
- [ ] 1.2 Add `arb_with_heredoc` proptest strategy in the same module,
      composing `arb_shell_chars` with synthesised `<<DELIM` /
      `<<'DELIM'` openers and matched / unmatched closers.
- [ ] 1.3 Re-export both strategies via `pub(crate) use` from
      `crates/engine/src/eval/tests/mod.rs` for test consumers.
- [ ] 1.4 Update existing `arb_input` in
      `crates/engine/src/eval/command.rs` to delegate to
      `arb_shell_chars` so the two existing proptests immediately
      benefit from the broader alphabet.

## 2. Invariant proptests

- [ ] 2.1 Add `prop_spans_within_input_bounds` in
      `crates/engine/src/eval/tests/properties.rs`, driven by
      `arb_with_heredoc`, asserting every `SegmentDecision` /
      `EvalUnit` / `ParseDiagnostic` span satisfies
      `0 ≤ start ≤ end ≤ input.len()`. (Spec: `parser-engine-invariants`
      § Emitted spans lie within input bounds.)
- [ ] 2.2 Add `prop_embedded_source_matches_span_slice`, driven by
      `arb_shell_chars`, asserting `&input[span]` equals the embedded
      source after applying the sigil-trim normalisation documented
      in the spec. (Spec: § Embedded command source matches its span.)
- [ ] 2.3 Add `prop_single_quoted_regions_are_inviolable`, driven by
      a hand-written strategy that injects literal `'…'` regions into
      `arb_shell_chars` output. (Spec: § Single-quoted regions are
      inviolable.)
- [ ] 2.4 Add `prop_quoted_heredoc_bodies_are_inviolable`, driven by
      `arb_with_heredoc`, asserting no `SimpleCommand` /
      `EmbeddedCommand` span lies strictly inside a `<<'DELIM'`
      body. (Spec: § Quoted heredoc bodies are inviolable.)
- [ ] 2.5 Add `prop_recursive_segments_stay_within_parent_span` in
      `properties.rs`, driven by `arb_shell_chars`, asserting nested
      `SegmentDecision` spans lie within their parent
      `EmbeddedCommand` span. (Spec: § Recursive evaluation stays
      within parent span.)
- [ ] 2.6 Add `prop_paren_matchers_agree` in `properties.rs`, driven
      by `arb_shell_chars`, asserting the lexer's
      `read_balanced_parens` and the engine's `find_balanced_paren`
      return the same offset for every `$()` in the input. Requires a
      thin test-only helper exposing the lexer position post-extract.
      (Spec: § Parser and engine agree on substitution boundaries.)

## 3. Regression seeds

- [ ] 3.1 Capture today's `git commit -m "$(cat <<'EOF' …`)`… EOF )"`
      input verbatim into
      `crates/engine/proptest-regressions/eval/properties.txt` as a
      seed for `prop_quoted_heredoc_bodies_are_inviolable`. Use the
      file format documented in `proptest`'s book.
- [ ] 3.2 Add a `#[test]` `regression_2026_05_11_proptest_command` in
      `crates/engine/src/eval/command.rs` `tests` mod that pins the
      exact input as a non-proptest reproducer, gated on `#[ignore]`
      with a comment linking to the follow-up AST-fix change ID.
      (Removed once the fix lands.)

## 4. Coverage and parser-side reach

- [ ] 4.1 Extend the alphabet of `segments_cover_input` in
      `crates/shell-parser/src/segment.rs` to include `` ` ``, `\\`,
      `<`, `>`, `#`. Verify no new failures emerge unrelated to
      today's bug; file any genuine failures as separate changes.
- [ ] 4.2 Add a doc-test or build-script check that every requirement
      in `openspec/specs/parser-engine-invariants/spec.md` is mapped
      to at least one `proptest!` function name in
      `crates/engine/src/eval/tests/properties.rs` (grep-based is
      sufficient).

## 5. Validation and rollout

- [ ] 5.1 Run `cargo test --workspace` and confirm only the
      regression-seed-bearing property is `#[ignore]`-gated; all
      other new properties pass on `main`.
- [ ] 5.2 Run `cargo test --workspace` twice, measure wall-time
      delta vs. pre-change baseline. Budget +5 s; if exceeded,
      either reduce `cases` for the slow property or split into a
      `slow` test cfg.
- [ ] 5.3 Run `cargo tarpaulin` and confirm coverage is not reduced
      in the touched modules (`decompose.rs`, `command.rs`,
      `string_readers.rs`). Inspect `lcov.info` for any
      newly-uncovered branches.
- [ ] 5.4 Run `cargo fmt` and `may-i fmt` over any touched example
      configs (none expected, but check).
- [ ] 5.5 Open follow-up change for the AST-level fix (spans on
      `WordPart`, nested substitution ASTs). Link from
      `tasks.md` § 3.2's `#[ignore]` comment.
- [ ] 5.6 Update `openspec/specs/testing-strategy/spec.md` after
      archive of this change; verify the new invariant classes
      appear in the merged spec.

## 1. Lexer `#` token-boundary fix

- [ ] 1.1 In `crates/shell-parser/src/lexer/word_parts.rs` (and any sibling
      word-text reader in `crates/shell-parser/src/lexer/mod.rs`), guard the
      `#`-as-comment-start branch on a token-boundary precondition. Inside an
      in-progress word, treat `#` as a literal character to be appended to the
      current word part.
- [ ] 1.2 Add unit tests in `crates/shell-parser/src/tests/word.rs`:
      `a#cat` → single `Literal("a#cat")`; `echo hi # comment` → two-word
      command with comment discarded; `'a # not'` → literal preserved.
- [ ] 1.3 Add an integration-level test that `a#cat <<'A'\nbody\nA` produces
      a single `SimpleCommand` with command word `a#cat` and a heredoc
      redirect whose body is `body\n`.
- [ ] 1.4 Verify against bash for ~5 representative inputs containing `#`
      mid-word (`v1.2#beta`, `colour#ff00ff`, `a#cat`, `echo a#b#c`,
      `tag#1.0`); behaviour SHALL match.

## 2. WordPart shape change

- [ ] 2.1 In `crates/shell-parser/src/ast/mod.rs`, convert
      `WordPart::CommandSubstitution`, `Backtick`, `Arithmetic` to struct-form
      variants with `source: String` and `span: Span` fields. Add `span: Span`
      to the existing `WordPart::ProcessSubstitution` struct variant.
- [ ] 2.2 Update derived impls and `serde` annotations as needed; the JSON
      shape becomes `{"command_substitution": {"source": "…", "span": [a, b]}}`.
- [ ] 2.3 Audit `examples/*.lisp` and any in-tree config files for stored JSON
      that might encode the old WordPart shape; none are expected, but
      confirm before merging.

## 3. Lexer span threading

- [ ] 3.1 In `crates/shell-parser/src/lexer/word_parts.rs` at the
      `Some('`')` arm: snapshot `body_start = self.byte_pos` after the opening
      backtick advance, snapshot `body_end = self.byte_pos` immediately
      before the close-skipping `advance()` (or at EOF), construct
      `WordPart::Backtick { source: s, span: Span::new(body_start, body_end) }`.
      Apply the same pattern at the second backtick arm.
- [ ] 3.2 In `crates/shell-parser/src/lexer/word_parts.rs` at the `$(` /
      `$((` arm: snapshot `body_start` after consuming `$(` (or `$((`),
      snapshot `body_end` after the body reader returns and before the
      close-skipping advance. Construct `Arithmetic` / `CommandSubstitution`
      with the captured span.
- [ ] 3.3 In `crates/shell-parser/src/lexer/mod.rs` at the
      `WordPart::ProcessSubstitution` construction site (~line 207): apply
      the same snapshot pattern to populate the new `span` field.
- [ ] 3.4 Verify all five construction sites produce
      `source.len() == span.end - span.start` via a temporary
      `debug_assert!` during development; remove before commit.

## 4. Engine `decompose` rewrite

- [ ] 4.1 In `crates/engine/src/eval/decompose.rs`, rewrite
      `push_embedded_units` to walk the AST's `WordPart`s and emit
      `EvalUnit::EmbeddedCommand { source, span }` directly from the AST
      span/source pair.
- [ ] 4.2 Delete `find_substitution_spans`, `find_balanced_paren`, and
      `find_arith_close` from `decompose.rs`. Update any test that referenced
      them.
- [ ] 4.3 Confirm `evaluate_command_inner` in
      `crates/engine/src/eval/command.rs` requires no changes (the recursion
      shape stays the same; correctness is now established by construction).

## 5. Consumer match-arm updates

- [ ] 5.1 Update all match arms in `crates/shell-parser/src/ast/word.rs`
      (`is_dynamic_in`, `has_dynamic_in`, `collect_embedded_commands`,
      `collect_dynamic_from`, `parts_to_str`) to handle the struct-form
      variants.
- [ ] 5.2 Update `crates/shell-parser/src/ast/helpers.rs` heredoc-cat-fold
      logic.
- [ ] 5.3 Update any pretty-printer / trace renderer arms that destructure
      `WordPart::CommandSubstitution` / `Backtick` / `Arithmetic` /
      `ProcessSubstitution`. Find with
      `grep -rn "WordPart::\(CommandSubstitution\|Backtick\|Arithmetic\|ProcessSubstitution\)" --include="*.rs" crates/`.
- [ ] 5.4 Run `cargo build --workspace` and resolve every exhaustiveness or
      pattern-shape error.

## 6. Threading-correctness proptests

- [ ] 6.1 In `crates/engine/src/eval/tests/properties.rs`, add a helper
      `walk_word_parts(cmd, |part| …)` that visits every `WordPart` in a
      parsed command (recursing through `DoubleQuoted`).
- [ ] 6.2 Add `prop_wordpart_source_matches_span_slice` driven by
      `arb_shell_chars` and `arb_with_heredoc`: for every dynamic
      `WordPart`, `&input[span.start..span.end] == source`.
- [ ] 6.3 Add `prop_wordpart_sibling_spans_monotonic_and_disjoint` driven by
      `arb_shell_chars`: within a single `Word`, spanned-sibling spans are
      ordered and non-overlapping.
- [ ] 6.4 Add `prop_wordpart_spans_within_input_bounds`: every dynamic
      `WordPart` span satisfies `0 ≤ start ≤ end ≤ input.len()`.
- [ ] 6.5 Add `prop_wordpart_reparse_round_trip`: for every
      `WordPart::CommandSubstitution`, `format!("{:?}", parse(source).command)
      == format!("{:?}", parse(&input[span]).command)`.
- [ ] 6.6 Update `requirement_to_property_mapping_is_complete` (in the
      sibling change) to include the new `Spec: § …` doc-comments mapping
      each new property to its requirement heading.

## 7. Un-gate previously-failing properties

- [ ] 7.1 Remove the `#[ignore = "…"]` attribute from
      `prop_spans_within_input_bounds`,
      `prop_embedded_source_matches_span_slice`,
      `prop_quoted_heredoc_bodies_are_inviolable`, and
      `regression_2026_05_11_proptest_command` in
      `crates/engine/src/eval/tests/properties.rs`.
- [ ] 7.2 Remove the now-unneeded `prop_assume!(!input.contains('\\'))` from
      `prop_embedded_source_matches_span_slice` (the inner-span semantics make
      the escape-skipping mismatch impossible).
- [ ] 7.3 Decide on `prop_paren_matchers_agree`: delete (the engine no longer
      has a mirror matcher) or repurpose as a parser-internal sanity check.
      Document the decision inline.
- [ ] 7.4 Run the full proptest battery: `cargo test --workspace`. Verify
      zero `#[ignore]` markers remain in the
      `parser_engine_invariants` module.

## 8. Validation and rollout

- [ ] 8.1 Run `cargo test --workspace` — all tests pass with no
      `#[ignore]` regressions.
- [ ] 8.2 Run `cargo tarpaulin` — coverage in
      `crates/shell-parser/src/lexer/word_parts.rs` and
      `crates/engine/src/eval/decompose.rs` does not decrease.
- [ ] 8.3 Run `cargo bench` (or wall-time `cargo test` before/after) — any
      delta over +5s is investigated.
- [ ] 8.4 Run `cargo fmt`. Run `may-i fmt` if any `examples/*.lisp` changed.
- [ ] 8.5 Update the test helper patch on `locate_quoted_heredoc_body` (if
      not already merged) so it filters comment-shadowed and quote-shadowed
      `<<'…'` openers.

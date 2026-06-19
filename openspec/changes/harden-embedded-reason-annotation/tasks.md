## 1. Structural annotation state (replace substring sniffing)

- [ ] 1.1 Write a failing engine test: `echo "$('a substitution in b')"` (inner command name contains the literal `substitution in`, no rule matches it) — the reason SHALL carry the origin clause naming `echo` and SHALL NOT be suppressed by the phrase in the command name.
- [ ] 1.2 Thread an "aggregate reason is already origin-annotated" boolean out of `eval_units` alongside its `EvalResult` (internal return; the three discarding call sites — `evaluate_command_with_fold`, `evaluate_authorised_string`, the token path — drop it). The `EmbeddedCommand` arm reads the inner flag to decide re-annotation and reports its own.
- [ ] 1.3 Drop both substring checks from `annotate_embedded_reason` (`contains(" substitution in ")` and `ends_with(" (embedded substitution)")`); it now wraps unconditionally, still falling back to the generic clause for a process substitution / unnameable owner.

## 2. Preserve existing annotation behaviour

- [ ] 2.1 Confirm the locked-output tests pass unchanged: `nested_embedded_substitution_does_not_double_wrap`, `embedded_dollar_substitution_names_outer_command`, `embedded_backtick_substitution_names_outer_command`, `annotate_embedded_reason_per_origin`, and the generic double-wrap regression. Adjust only call sites, never expected strings.

## 3. Make the escaping invariant load-bearing

- [ ] 3.1 Extend the input generator behind `prop_reason_is_single_line` to emit control-character vectors (ANSI-C `$'\n'`/`$'\t'` command-name forms and raw control bytes) so a control character provably reaches a reason-interpolated name.
- [ ] 3.2 Add a focused regression test pinning one explicit control-char-in-command-name case (reason contains no raw newline), complementing the existing `control_chars_in_command_name_are_escaped_in_reason`.

## 4. Coverage & hygiene

- [ ] 4.1 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for any newly-uncovered branch in the reworked `annotate_embedded_reason` / `eval_units` flag path.
- [ ] 4.2 Check in any new `proptest-regressions/` files the broadened generator produces.
- [ ] 4.3 Review REFERENCE.md: if it documents substitution-origin reason annotations, confirm the example labels still match (this change alters no label text); otherwise record "verified, no surface change".

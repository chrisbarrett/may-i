## 1. Structural annotation state (replace substring sniffing)

- [x] 1.1 Write a failing engine test: `echo "$('a substitution in b')"` (inner command name contains the literal `substitution in`, no rule matches it) — the reason SHALL carry the origin clause naming `echo` and SHALL NOT be suppressed by the phrase in the command name.
- [x] 1.2 Thread an "aggregate reason is already origin-annotated" boolean out of `eval_units` alongside its `EvalResult` (internal return; the three discarding call sites — `evaluate_command_with_fold`, `evaluate_authorised_string`, the token path — drop it). The `EmbeddedCommand` arm reads the inner flag to decide re-annotation and reports its own.
- [x] 1.3 Drop both substring checks from `annotate_embedded_reason` (`contains(" substitution in ")` and `ends_with(" (embedded substitution)")`); it now wraps unconditionally, still falling back to the generic clause for a process substitution / unnameable owner.

## 2. Preserve existing annotation behaviour

- [x] 2.1 Confirm the locked-output tests pass unchanged: `nested_embedded_substitution_does_not_double_wrap`, `embedded_dollar_substitution_names_outer_command`, `embedded_backtick_substitution_names_outer_command`, `annotate_embedded_reason_per_origin`, and the generic double-wrap regression. Adjust only call sites, never expected strings.

## 3. Make the escaping invariant load-bearing

- [x] 3.1 Extend the input generator behind `prop_reason_is_single_line` to emit control-character vectors (ANSI-C `$'\n'`/`$'\t'` command-name forms and raw control bytes) so a control character provably reaches a reason-interpolated name.
- [x] 3.2 Add a focused regression test pinning one explicit control-char-in-command-name case (reason contains no raw newline), complementing the existing `control_chars_in_command_name_are_escaped_in_reason`.

## 4. Coverage & hygiene

- [x] 4.1 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for any newly-uncovered branch in the reworked `annotate_embedded_reason` / `eval_units` flag path.
- [x] 4.2 Check in any new `proptest-regressions/` files the broadened generator produces.
- [x] 4.3 Review REFERENCE.md: if it documents substitution-origin reason annotations, confirm the example labels still match (this change alters no label text); otherwise record "verified, no surface change".

## 5. Enforce display-safety in the type system (D3)

- [x] 5.1 Write a failing unit proptest: `DisplaySafe::new(s)` produces a value whose string form contains no `char::is_control()` for any input `s` (including raw control bytes), and is idempotent (`DisplaySafe::new(DisplaySafe::new(s)) == DisplaySafe::new(s)`).
- [x] 5.2 Add a `DisplaySafe` newtype (engine crate, `display_safe` module) with a private field and one escaping smart constructor (`DisplaySafe::new` runs the control-escape over the whole string). Impl `Deref<Target = str>`, `Display`, `Clone`/`Debug`/`PartialEq`/`Eq`. The old `escape_for_reason` body becomes the module-private `escape_control`. (No `From`/`AsRef`/`PartialEq<str>`/`Serialize`: per code-review, an escaping `From` violates the lossless-conversion contract and the others were dead — every construction goes through the explicit `DisplaySafe::new`; the one JSON site serialises via `as_deref()`.)
- [x] 5.3 Change `EvalResult.reason` to `Option<DisplaySafe>` and `EvalResult::new` to take `Option<DisplaySafe>`. Build the `DisplaySafe` at each reason's origin so the value passed to `fold.default_ask` and the one stored on the result are both escaped (covers the audit/trace surface, not only the result).
- [x] 5.4 Delete every now-redundant per-site `escape_for_reason(name)` call (command.rs, decompose.rs, entry.rs) — including reverting the D2-review `DynamicCommand` point-escape, now subsumed by the sink. `escape_for_reason` is gone; its body lives as the `display_safe` module's private `escape_control`.
- [x] 5.5 Fix all consumers: engine internals, `src/` output/audit/render/json, and tests. `reason.as_deref()` readers keep working via `Deref`; serialization and `String`-typed DTO fields (`AuditTap`, `CheckResult`, effect results) convert via `to_string`/`as_deref`.
- [x] 5.6 Confirm the existing reason-invariant tests still pass and now hold by type: `prop_reason_is_single_line` becomes a wiring check (the type makes a raw control char unrepresentable); the per-`DisplaySafe::new` proptest is the primary proof.
- [x] 5.7 `cargo fmt`; full workspace test; `cargo clippy` clean; no `examples/*.lisp` touched. Re-run the code-review reviewers for sign-off.

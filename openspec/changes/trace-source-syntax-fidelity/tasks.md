## 1. Failing tests for syntax fidelity

- [ ] 1.1 Add a unit test in `src/annotation.rs` (`tests` mod) constructing a rule containing `ArgPattern::Tail` and asserting the rendered Doc text contains `(tail (authorise))` and does not contain `<unknown-arg-pattern>`.
- [ ] 1.2 Add a unit test constructing a rule with `(parameter "c" (authorise))` (i.e. `ArgPattern::Parameter` + `ParameterForm::MayI`) and asserting the rendered Doc text contains `(parameter "c" (authorise))` and does not contain `(may-i *)`.
- [ ] 1.3 Add unit tests for `effect_terminal` covering Allow/Ask/Deny × with-reason / without-reason. Assert each renders as `(allow "r")`/`(allow)`/etc., and that `(effect :allow …)` does not appear in the rendered Doc text.
- [ ] 1.4 Verify all four tests fail before any implementation changes.

## 2. Failing tests for tail/parameter annotations

- [ ] 2.1 Add a unit or integration test (probably under `tests/check_integration.rs`) for `direnv exec true` matching a rule with `(tail (authorise))` and asserting the right column for the `(tail (authorise))` line contains `tail = "true"`.
- [ ] 2.2 Add a test for a multi-token tail (`direnv exec echo hi there`) asserting the annotation reads `tail = "echo hi there"`.
- [ ] 2.3 Add a test for `bash -c "echo hi"` matching `(parameter "c" (authorise))` asserting the right column for the `(parameter …)` line contains `value = "echo hi"`.
- [ ] 2.4 Add a test for `bash -c "echo hi there"` asserting `value = "echo hi there"`.
- [ ] 2.5 Verify all four tests fail before implementation.

## 3. Implementation: ArgPattern rendering

- [ ] 3.1 In `src/annotation.rs`, replace the `_ =>` fallthrough in `arg_pattern_to_doc` with explicit arms for every `ArgPattern` variant. Add a `Tail` arm that returns `Doc::list(vec![Doc::atom("tail"), Doc::list(vec![Doc::atom("authorise")])])`.
- [ ] 3.2 In the same function, change the `ParameterForm::MayI` arm to return `Doc::list(vec![Doc::atom("authorise")])` instead of `Doc::list(vec![Doc::atom("may-i"), Doc::atom("*")])`.
- [ ] 3.3 Confirm `cargo build --workspace` enforces exhaustiveness — temporarily delete one variant arm to verify a non-exhaustive-match error fires, then restore it.
- [ ] 3.4 Run tests from step 1.1 and 1.2; confirm green.

## 4. Implementation: Effect terminal rendering

- [ ] 4.1 In `src/annotation.rs`, modify `TracingFold::effect_terminal` to construct the display Doc by calling `effect.to_doc()` (the canonical `Effect::to_doc` from `crates/core/src/ast.rs`) and wrapping it via `unannotated_to_ann`. Attach the existing `Ann::EffectDecision` annotation to the resulting Doc node.
- [ ] 4.2 Verify that the right-column annotation produced from `Ann::EffectDecision` still renders as `→ :allow "reason"` etc. (renderer code unchanged).
- [ ] 4.3 Run tests from step 1.3; confirm green.

## 5. Implementation: tail annotation

- [ ] 5.1 In `crates/engine/src/eval/effects.rs`, extend `ArgMatchDetail` with `captured_value: Option<String>` (default `None`).
- [ ] 5.2 In `evaluate_tail_authorise_fold`, when the tail slice is captured, set `captured_value: Some(tail_slice.join(" "))` and `search_tokens: vec![]`. Apply to both the recursive-success and the recursive-failure paths so the annotation is present even on the no-recursion match path.
- [ ] 5.3 In `src/output/render_rule.rs`, when the `ArgMatch` annotation has `captured_value: Some(v)` AND the predicate Doc head is `tail`, format the right column as `tail = "<v>"`. Skip the existing `∈ { … }` formatting in this case.
- [ ] 5.4 Run tests from steps 2.1 and 2.2; confirm green.

## 6. Implementation: parameter-authorise annotation

- [ ] 6.1 In `crates/engine/src/eval/effects.rs::evaluate_parameter_fold`, before delegating to `recurse_into_inner_command` in the `ParameterForm::MayI` branch, emit an `effect_arg_match` carrying `ArgMatchDetail { search_tokens: vec![], captured_value: Some(value.clone()), arg_set: ctx.args.to_vec(), matched: true, positional_elements: vec![] }`. Make sure the recursion still runs and produces its inner trace.
- [ ] 6.2 In `src/output/render_rule.rs`, when the `ArgMatch` annotation has `captured_value: Some(v)` AND the predicate Doc head is `parameter`, format the right column as `value = "<v>"`.
- [ ] 6.3 Verify the inner trace block still appears beneath the rule for `bash -c "echo hi"`.
- [ ] 6.4 Run tests from steps 2.3 and 2.4; confirm green.

## 7. JSON output

- [ ] 7.1 In `src/output/json.rs`, serialise `captured_value` on the `ArgMatch` annotation when present (omit when `None`).
- [ ] 7.2 Add a JSON test asserting `(tail (authorise))` and `(parameter X (authorise))` ann blocks include `"captured_value": "<v>"`.

## 8. Snapshot updates

- [ ] 8.1 Run `cargo test --workspace`. List all failing snapshot tests touching trace text (likely under `crates/engine/src/test_generators/`, `src/snapshots/`, `tests/check_integration.rs`).
- [ ] 8.2 Run `cargo insta review` (or hand-edit non-insta snapshots) to accept the new syntax-fidelity output.
- [ ] 8.3 Spot-check at least three snapshot diffs to confirm only the targeted changes appear: `<unknown-arg-pattern>` → `(tail (authorise))`, `(may-i *)` → `(authorise)`, `(effect :X …)` → `(X …)`, and the new `tail = "…"` / `value = "…"` annotations.

## 9. Manual verification

- [ ] 9.1 Run `cargo run --quiet --bin may-i -- check` against a config that exercises `(tail (authorise))` (e.g. starter config with `direnv exec true`); confirm rendered trace shows `(tail (authorise))` with `tail = "true"` annotation.
- [ ] 9.2 Run against a config that exercises `(parameter "c" (authorise))` (e.g. `bash -c "echo hi"` failing check); confirm rendered trace shows `(parameter "c" (authorise))` with `value = "echo hi"` annotation and an inner trace beneath.
- [ ] 9.3 Run against any failing check that has a terminal effect with a reason (e.g. `(allow "non-force push")`); confirm rendered trace shows `(allow "non-force push")` and the right column reads `→ :allow "non-force push"`.

## 10. Coverage

- [ ] 10.1 Run `cargo tarpaulin` and inspect `lcov.info` for the new arms in `src/annotation.rs`, `crates/engine/src/eval/effects.rs`, and `src/output/render_rule.rs`. Add targeted tests for any uncovered branches (e.g. tail with empty slice, parameter-authorise with missing value).

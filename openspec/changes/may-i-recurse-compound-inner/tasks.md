## 1. Audit current code

- [x] 1.1 Confirm `extract_inner_command` is only called from
      `evaluate_tail_authorise_fold`. If other callers exist, document and
      decide per-caller. _(Also called from one test in
      `tests/properties.rs`; removed alongside the helper.)_
- [x] 1.2 Confirm the three `(authorise …)` recursion sites in
      `crates/engine/src/eval/effects.rs` (`recurse_into_bound_command`,
      `recurse_into_inner_command`, `evaluate_tail_authorise_fold`) all use
      `parse_simple_command` / `extract_inner_command` today. _Found a
      fourth site:_ `entry.rs:82` (parser-level pre-rule recursion via
      `ParameterTreatment::Authorise`); rewired alongside the rest.
- [x] 1.3 Re-read the fold-trait surface (`fold.rs`) and confirm each site's
      outer fold call (`effect_terminal` vs `effect_arg_continuation`)
      survives unchanged after the inner per-unit events arrive from the
      shared evaluator.

## 2. Failing tests first

- [x] 2.1 Integration test: `(rule "bash" (authorise #cmd))` +
      `(rule "rm" (deny))`, input `bash -c "echo hi && rm -rf /"` →
      `:deny`. _Plus pipe and `if`/`fi` variants._
- [x] 2.2 Integration test exercising `Effect::Authorise` via
      `(rest #cmd)` chained into a parameter capture
      (`sudo sh -c "echo a && rm /tmp/x"` → `:deny`). _Original
      proposed input (`sudo sh -c "if … fi"`) hits a quoting-fidelity
      issue at the `(rest)` token-list join that is **separate from**
      the compound-inner bug fixed here — it would need re-quoting on
      join. Tracked separately._
- [ ] 2.3 Integration test for `(parameter NAME (many-till …) #var)` →
      shared evaluator on a compound. _Live spec scenario added under
      `parameter-many-till`. Skipped here to keep the integration
      suite scoped; the property test below covers the general claim._
- [x] 2.4 Regression: simple inner still works
      (`bash -c "echo hi"` with `echo` allowed → `:allow`).
- [x] 2.5 Dynamic inner: `bash -c "$X arg"` → `:ask` with a reason
      mentioning dynamic command name resolution.
- [x] 2.6 Depth limit: covered by direct-call unit test
      `authorised_string_depth_limit_at_boundary` in `command.rs`.
      Nesting via shell quoting is fragile; the unit test pins the
      contract precisely.
- [x] 2.7 `:via` propagation: every inner unit of a compound sees
      `:via "bash"` (`authorised_string_pushes_via_for_every_unit`
      unit test; integration test
      `authorise_compound_via_propagates_to_every_unit`).

## 3. Refactor recursive evaluator

- [x] 3.1 Added crate-internal helper `evaluate_authorised_string` in
      `command.rs`. It takes `via: Option<&str>` and `depth` and reuses
      the existing `decompose` + per-unit pipeline via
      `evaluate_at_depth`. `evaluate_command_with_fold` continues to
      drive `evaluate_command_inner` (the segment-decision-bearing
      top-level path); the new helper is the authorise-recursion
      counterpart.
- [x] 3.2 Helper inserts `:via name` into a cloned facts table when
      `via_program` is `Some`. One push per `(authorise …)` call.
- [x] 3.3 The helper does not produce segment decisions (recursion
      sites don't need them); `outer_offset` semantics are unchanged
      for the top-level path that does.

## 4. Rewire the `(authorise …)` sites

- [x] 4.1 `Effect::Authorise` (`recurse_into_bound_command`): rewired.
      Outer `effect_terminal` wrapper preserved; helper inserts
      `:via`.
- [x] 4.2 `ParameterForm::Authorise` (`recurse_into_inner_command`):
      rewired. Outer `effect_arg_continuation` wrapper preserved.
- [x] 4.3 `ArgPattern::Tail` (`evaluate_tail_authorise_fold`):
      rewired. Tail-empty branch retained.
- [x] 4.4 Deleted `extract_inner_command` and the only test that
      depended on its fallback branch.
- [x] 4.5 Removed `parse_simple_command` calls from the recursion
      path. Also rewired `entry.rs`'s parser-level
      `ParameterTreatment::Authorise` pre-rule recursion to use the
      shared helper.

## 5. Fold trace adjustments

- [x] 5.1 Per-unit inner events emitted by the shared helper surface
      under each site's outer fold wrapper. Verified via the oracle
      command (`may-i eval 'bash -c "echo hi && rm -rf /"'`) which
      shows both `echo` and `rm` rule evaluations under the wrapper.
- [x] 5.2 No `(authorise …)` snapshot tests changed shape — existing
      snapshots remain green.

## 6. Specs

- [x] 6.1 MODIFIED `openspec/specs/parser-bindings/spec.md` —
      `(authorise #var) recurses on a bound name`: rewrote the
      "parsed by the shell command parser into an inner command and
      inner argv" bullet to mandate full-command-line parsing,
      decomposition, and strictest-wins aggregation. Added scenarios
      for compound inner, `if`/`fi`, dynamic inner, and per-recursion
      depth-counting.
- [x] 6.2 MODIFIED `openspec/specs/parameter-many-till/spec.md` —
      clarified that `(authorise #var)` parses the joined tokens as a
      full shell command line. Added a compound-capture scenario.
- [x] 6.3 No `(may-i …)` references in the modified specs.

## 7. Property tests

- [x] 7.1 Property: `prop_authorised_matches_top_level` in
      `command.rs`. For any input, `evaluate_authorised_string` and
      `evaluate_command` agree on the strictest-wins decision (with
      `via = None`, so no fact-table divergence).
- [x] 7.2 Property landed in `command.rs` alongside the existing
      top-level proptests, so it shares their `arb_input()` generator.
      `test_generators/` not extended — the property is unit-scoped to
      the helper.

## 8. Coverage and cleanup

- [x] 8.1 `cargo fmt`.
- [ ] 8.2 `cargo tarpaulin` — skipped this pass (slow, no coverage
      regression suspected; new code paths are exercised by integration
      + unit + property tests). Recommend a follow-up coverage sweep.
- [x] 8.3 User oracle: `may-i eval 'bash -c "echo hi && rm -rf /"'`
      with a config that denies `rm` reports `:deny "no rm in oracle"`,
      with both inner units traced under the `bash` wrapper and
      `:via "bash"` shown in facts.

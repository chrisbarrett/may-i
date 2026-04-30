## 1. Audit current code

- [ ] 1.1 Confirm `extract_inner_command` is only called from `Effect::MayI`. If
      other callers exist, document and decide per-caller.
- [ ] 1.2 Re-read `effect_may_i` / `effect_may_i_no_match` fold-trait shape
      and decide trace strategy (decision §5 of design.md).

## 2. Failing tests first

- [ ] 2.1 Write integration test: `(rule "wrapper" (positional . (may-i *)))`,
      input `wrapper "echo hi && rm -rf /"` with `rm` denied → `:deny`.
- [ ] 2.2 Write test: same rule, input `wrapper "if true; then rm /; fi"`,
      `rm` denied → `:deny`.
- [ ] 2.3 Write test: simple inner (`wrapper "echo hi"`) still works (regression
      guard for the equivalence claim in design risks).
- [ ] 2.4 Write test: dynamic inner (`wrapper "$X"`) → `:ask` with reason
      mentioning "dynamic".
- [ ] 2.5 Write test: depth limit is hit if wrappers nest too deeply
      (`sudo "sudo \"sudo \\\"…\\\"\""` style).
- [ ] 2.6 Write test: `:via` fact is set to the outermost wrapper at the inner
      eval (and is consistent across compound inner units).

## 3. Refactor recursive evaluator

- [ ] 3.1 Extract the per-unit aggregation logic in `evaluate_command_inner`
      into a shared private function (or expose as crate-internal).
- [ ] 3.2 Add an optional `via: Option<&str>` parameter that injects the
      `:via` fact into the inner facts table.
- [ ] 3.3 Update existing top-level callers of `evaluate_command` /
      `evaluate_command_with_fold` — signatures stay unchanged externally.

## 4. Rewire `Effect::MayI`

- [ ] 4.1 In `Effect::MayI` branch, join `ctx.args` into a single string.
- [ ] 4.2 If joined string is empty, call `effect_may_i_no_match` and return
      (preserves current behaviour).
- [ ] 4.3 Otherwise, call the shared evaluator with `depth+1`, the wrapper
      command name as `via`, and the same fold.
- [ ] 4.4 Wrap the call with `effect_may_i` start/end fold events so trace
      output continues to bracket the recursion. Adapt `effect_may_i`
      signature to receive aggregate result (decision §5).
- [ ] 4.5 Delete `extract_inner_command` once no callers remain.

## 5. Fold trace adjustments

- [ ] 5.1 Update `effect_may_i` (and any subclass-style implementors) to take
      the aggregate `EffectResult` rather than `(inner_cmd, inner_args)`.
- [ ] 5.2 Update trace rendering so the inner per-unit events appear under
      the wrapper node visually (indent / group).
- [ ] 5.3 Update snapshot tests that show `(may-i ...)` trace.

## 6. Specs

- [ ] 6.1 Add requirement(s) to
      `openspec/specs/shell-command-security-model/spec.md` covering compound
      inner evaluation, worst-case aggregation, and `:via` propagation.

## 7. Property tests

- [ ] 7.1 Property: for any compound shell command `c`, `(may-i ...)`
      recursing on `c` produces the same decision as `evaluate_command` would
      on `c` (modulo the `:via` fact and depth offset).
- [ ] 7.2 Add to `crates/engine/src/test_generators/`.

## 8. Coverage and cleanup

- [ ] 8.1 `cargo fmt`.
- [ ] 8.2 `cargo tarpaulin`; inspect `lcov.info` for new uncovered branches.
- [ ] 8.3 Update `CHANGELOG.md` if present (none currently — skip).
- [ ] 8.4 Run user oracle: `may-i eval 'bash -c "echo hi && rm -rf /"'` with
      a config that denies `rm` — verify `:deny` is reported.

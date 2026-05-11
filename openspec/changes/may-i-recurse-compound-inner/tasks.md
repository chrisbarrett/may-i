## 1. Audit current code

- [ ] 1.1 Confirm `extract_inner_command` is only called from
      `evaluate_tail_authorise_fold`. If other callers exist, document and
      decide per-caller.
- [ ] 1.2 Confirm the three `(authorise …)` recursion sites in
      `crates/engine/src/eval/effects.rs` (`recurse_into_bound_command`,
      `recurse_into_inner_command`, `evaluate_tail_authorise_fold`) all use
      `parse_simple_command` / `extract_inner_command` today.
- [ ] 1.3 Re-read the fold-trait surface (`fold.rs`) and confirm each site's
      outer fold call (`effect_terminal` vs `effect_arg_continuation`)
      survives unchanged after the inner per-unit events arrive from the
      shared evaluator.

## 2. Failing tests first

- [ ] 2.1 Integration test: `(parser "bash" (parameter "c" #cmd))` +
      `(rule "bash" (authorise #cmd))` + `(rule "rm" (deny))`,
      input `bash -c "echo hi && rm -rf /"` → `:deny`.
- [ ] 2.2 Integration test: `(parser "sudo" (rest #cmd))` +
      `(rule "sudo" (authorise #cmd))` + `(rule "rm" (deny))`,
      input `sudo sh -c "if true; then rm /; fi"` → `:deny`.
      (Exercises `Effect::Authorise` via `(rest …)`.)
- [ ] 2.3 Integration test: `(parser "find" (parameter "exec" (many-till …) #args))`
      + `(rule "find" (authorise #args))`, input
      `find . -exec sh -c "echo a && rm /tmp/x" \;` with `rm` denied →
      `:deny`. (Exercises `(parameter NAME (many-till …) #var)` capture
      → shared evaluator on a compound.)
- [ ] 2.4 Regression test: simple inner still works
      (`bash -c "echo hi"` with `echo` allowed → `:allow`).
- [ ] 2.5 Dynamic inner test: `bash -c "$X arg"` → `:ask` with a reason
      mentioning dynamic command name resolution.
- [ ] 2.6 Depth limit test: nested wrappers
      (`sudo sh -c "sudo sh -c \"sudo …\""`) hit the depth limit; reason
      mentions the limit.
- [ ] 2.7 `:via` propagation test: per-unit inner evaluations of a
      compound all see `:via` set to the outermost wrapper.

## 3. Refactor recursive evaluator

- [ ] 3.1 Extract `evaluate_command_inner`'s body into a crate-internal
      helper. Signature gains `via: Option<&str>`. Public
      `evaluate_command_with_fold` becomes a thin wrapper that passes
      `via = None`.
- [ ] 3.2 Inside the helper, if `via` is `Some(name)`, insert
      `:via name` into the facts before evaluating units.
- [ ] 3.3 Confirm `outer_offset` semantics still work end-to-end (segment
      decisions reported in outermost coordinates).

## 4. Rewire the three `(authorise …)` sites

- [ ] 4.1 `Effect::Authorise` (`recurse_into_bound_command`): replace the
      `parse_simple_command` block with a call to the shared evaluator.
      Pass `via = Some(ctx.command)`, `depth = ctx.recursion_depth + 1`,
      `outer_offset = 0`. Preserve the existing empty-value short-circuit
      and the outer `effect_terminal` fold wrapper.
- [ ] 4.2 `ParameterForm::Authorise` (`recurse_into_inner_command`):
      same rewrite. Preserve the outer `effect_arg_continuation` fold
      wrapper. The `:via` facts merge stays — only the parse/recurse
      core changes.
- [ ] 4.3 `ArgPattern::Tail` (`evaluate_tail_authorise_fold`): same
      rewrite. Preserve the existing tail-empty / boundary-absent
      branches before calling the shared evaluator.
- [ ] 4.4 Delete `extract_inner_command` once no callers remain.
- [ ] 4.5 Drop the per-site `parse_simple_command` imports / calls from
      the recursion path. `parse_simple_command` itself stays — other
      consumers (display, migration) may still use it.

## 5. Fold trace adjustments

- [ ] 5.1 Verify per-unit inner events emitted by the shared evaluator
      surface under each site's outer fold wrapper (no orphaned events,
      no double-counting).
- [ ] 5.2 Update snapshot tests that show `(authorise …)` trace output
      for compound inputs.

## 6. Specs

- [ ] 6.1 MODIFY `openspec/specs/parser-bindings/spec.md` —
      `(authorise #var) recurses on a bound name`: replace
      "parsed by the shell command parser into an inner command and
      inner argv" with "parsed by the shell command parser as a full
      command line, decomposed into evaluation units, and each unit
      evaluated against the active rule set, returning the strictest
      decision". Add a scenario for compound inner.
- [ ] 6.2 MODIFY `openspec/specs/parameter-many-till/spec.md` —
      the `(authorise #var)` usage clause: clarify that the joined
      tokens are parsed as a full shell command (compound forms
      supported), not as a single simple command.
- [ ] 6.3 Verify no `(may-i …)` references leak into the modified specs
      (use only current vocabulary: `(authorise #var)`, `(deny)`,
      `#var` bindings).

## 7. Property tests

- [ ] 7.1 Property: for any compound shell command `c` accepted by
      `parse`, evaluating `bash -c c` (with a parser declaring
      `(parameter "c" #cmd)` + `(authorise #cmd)`) produces the same
      strictest decision as evaluating `c` directly at the top level,
      modulo the `:via "bash"` fact and the +1 depth.
- [ ] 7.2 Add to `crates/engine/src/test_generators/`.

## 8. Coverage and cleanup

- [ ] 8.1 `cargo fmt`.
- [ ] 8.2 `cargo tarpaulin`; inspect `lcov.info` for new uncovered
      branches in the rewired sites.
- [ ] 8.3 Run user oracle:
      `may-i eval 'bash -c "echo hi && rm -rf /"'` with a config that
      denies `rm` — verify `:deny` is reported.

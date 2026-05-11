## Why

The `(authorise #var)` form is the rule-grammar mechanism for re-evaluating an
inner command captured by a parser binding. It re-parses the bound value as a
command and runs the rule engine over it. This is how wrappers like `sudo`,
`bash -c`, `xargs`, and `find -exec` are policed against the rules for the
program they actually invoke.

Today every recursion site uses `parse_simple_command` (or
`extract_inner_command`, which wraps it). That parser returns `None` for any
compound command and the call sites fall back to "first arg as command, rest
as args". So a user who runs

```
bash -c "echo hi && rm -rf /"
```

with a `(parser "bash" (parameter "c" #cmd))` + `(rule "bash" (authorise #cmd))`
gets `:ask` (or worse, `:allow`) — neither `echo` nor `rm` is evaluated. The
check the user expected the rule to perform never happens.

This is the same recursive evaluation that the top-level `evaluate_command_inner`
already does correctly: parse, decompose into `EvalUnit`s, evaluate each,
aggregate strictest. The `(authorise …)` recursion should reuse that machinery.

The bug is duplicated across **three** recursion sites in
`crates/engine/src/eval/effects.rs`:

1. `recurse_into_inner_command` — `(parameter NAME (authorise))` single-token
   capture (≈L723).
2. `recurse_into_bound_command` — `Effect::Authorise { binding }`, the surface
   `(authorise #var)` form (≈L235).
3. `evaluate_tail_authorise_fold` — `ArgPattern::Tail`, the
   `(tail (authorise))` form (≈L412), which uses `extract_inner_command`.

All three should funnel through one shared recursive evaluator.

## What Changes

- **`(authorise …)` recursion evaluates compound inner commands.** When the
  bound value forms a compound shell expression (pipelines, `&&`/`||`,
  sequences, `if`/`for`/`case`, command substitutions), the value is re-parsed
  as a full shell command, decomposed into `EvalUnit`s, and each unit
  evaluated against the rules. The recursion returns the strictest
  (most-restrictive) decision, matching the top-level evaluator's
  strictest-wins semantics.
- **A single shared recursive evaluator backs all three sites.** The body of
  `evaluate_command_inner` is extracted into a helper that takes an
  optional `via` and an initial depth. `Effect::Authorise`,
  `ParameterForm::Authorise`, and `ArgPattern::Tail` all call it.
- **`extract_inner_command` and direct `parse_simple_command` calls are
  retired from the recursion path.** Removed once no callers remain.
- **Recursion depth is preserved across the new path.** Each `(authorise …)`
  recursion counts as one step toward `recursion_limit`; multiple inner
  units within a single recursion SHALL NOT each consume a level.
- **The `:via` fact is preserved.** Each recursion site continues to push
  the wrapper command name onto the `:via` set before evaluating the
  inner.
- **Trace output reflects multiple inner units.** When `(authorise …)`
  recurses into a compound, the trace shows each contained simple
  command's evaluation rather than a single opaque entry.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `parser-bindings`: the `(authorise #var)` requirement is extended so the
  recursion contract covers compound inner commands (`bash -c "a && b"`,
  `sudo sh -c "if …; fi"`, etc.).
- `parameter-many-till`: the `(authorise #var)` rule-body usage clause is
  clarified to require full shell parsing of the joined capture.

## Impact

- `crates/engine/src/eval/command.rs` — `evaluate_command_inner` is the
  shared recursive evaluator. Either expose it crate-internal with a
  `via: Option<&str>` parameter, or extract a new helper that both
  `evaluate_command_with_fold` and the three `(authorise …)` sites call.
- `crates/engine/src/eval/effects.rs` —
  - `recurse_into_inner_command` (≈L723): replace `parse_simple_command`
    fallback with the shared evaluator.
  - `recurse_into_bound_command` (≈L235): same.
  - `evaluate_tail_authorise_fold` (≈L412): same; `extract_inner_command`
    becomes unused.
  - `extract_inner_command` (≈L934): delete once no callers remain.
- `crates/engine/src/fold.rs` — fold-trait surface may need a small tweak
  so per-unit inner trace events surface under the wrapper node rather
  than appearing flat.
- `crates/engine/src/eval/tests/mod.rs` — existing `(authorise …)` tests
  continue to pass; new tests cover compound inner.
- `tests/` (integration) — add scenarios for `bash -c "a && b"`,
  `sudo sh -c "if …; fi"`, denied inner inside compound, dynamic inner.
- `openspec/specs/parser-bindings/spec.md` — MODIFY the
  `(authorise #var)` requirement.
- `openspec/specs/parameter-many-till/spec.md` — MODIFY the
  `(authorise #var)` usage clause for `(many-till …)` captures.

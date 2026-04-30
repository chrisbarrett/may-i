## Why

`(may-i ...)` recursion is the rule-grammar mechanism for evaluating
command-runner builtins (`sudo`, `bash -c`, `eval`, `xargs`, `nix shell
--command`, etc.). It re-parses the inner argument as a command and runs the
rule engine over it.

Today the recursion path uses `parse_simple_command`, which returns `None` for
any compound command. The current fallback then treats the literal compound
string as a single command name, so no rule will match it. A user who runs

```
bash -c "echo hi && rm -rf /"
```

with a `(may-i *)` rule for `bash` gets `:ask` with an unhelpful reason —
neither `echo` nor `rm` is evaluated. The check that the user expected the rule
to perform never happens.

This is the same recursive evaluation that `evaluate_command_inner` already does
correctly at the top level: parse, decompose into `EvalUnit`s, evaluate each,
aggregate worst-case. `(may-i ...)` should reuse that machinery.

## What Changes

- **`Effect::MayI` evaluates compound inner commands.** When the args passed to
  `(may-i ...)` form a compound shell expression (pipelines, `&&`/`||`,
  sequences, `if`/`for`/`case`, command substitutions), the inner string is
  re-parsed as a full shell command, decomposed into `EvalUnit`s, and each unit
  evaluated against the rules. The recursion returns the worst-case
  (most-restrictive) decision.
- **`extract_inner_command` is retired or restricted.** The ad-hoc
  `parse_simple_command` + first-arg fallback is removed in favour of the
  shared `evaluate_command_inner` flow.
- **Recursion depth is preserved across the new path.** The existing
  `recursion_depth` / `recursion_limit` fields continue to bound nesting.
- **The `:via` fact is preserved.** The wrapper command name continues to be
  injected so rules like `(fact? [:via "sudo"])` keep working.
- **Trace output reflects multiple inner units.** When `(may-i ...)` recurses
  into a compound, the trace shows each contained simple command's evaluation
  rather than a single opaque entry.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `shell-command-security-model`: extended so the recursive evaluation
  contract covers compound inner commands inside `(may-i ...)`.

## Impact

- `crates/engine/src/eval/effects.rs` — `Effect::MayI` branch (≈L215) and
  `extract_inner_command` (≈L363). Replace with a call into the existing
  decompose + per-unit evaluate flow.
- `crates/engine/src/eval/command.rs` — `evaluate_command_inner` becomes (or
  exposes) the shared recursive evaluator; signature may grow a `:via` fact
  parameter and an initial depth.
- `crates/engine/src/fold.rs` — `effect_may_i` may need to accept multiple
  inner outcomes (or a single aggregated outcome) so traces remain coherent.
- `crates/engine/src/eval/tests/mod.rs` — existing MayI tests continue to pass;
  new tests cover compound inner.
- `tests/` (integration) — add scenarios for `bash -c "a && b"`, `eval "if …
  fi"`, denied inner inside compound.
- `openspec/specs/shell-command-security-model/spec.md` — new requirement(s)
  added by this change.

## Context

The engine has two near-parallel pieces of code that both "evaluate a string as
a shell command":

1. **`evaluate_command_inner`** (`crates/engine/src/eval/command.rs`) — top-level
   entry point used by `cmd_eval`, `cmd_claude_code_hook`, etc. Parses, calls
   `decompose`, evaluates each `EvalUnit`, aggregates worst-case, applies
   parse-error floor. Handles compound input correctly.

2. **`Effect::MayI`** (`crates/engine/src/eval/effects.rs:215`) — the
   recursive evaluator inside the rule engine. Calls `extract_inner_command`,
   which uses `parse_simple_command` and falls back to "first arg as command,
   rest as args". Does **not** decompose. Compound inner commands fall through
   to the broken fallback.

The asymmetry is the bug. The fix is to collapse the second path into the first
(or share a helper).

## Goals / Non-Goals

**Goals:**
- `(may-i ...)` correctly evaluates any shell command the top-level evaluator
  can evaluate.
- Worst-case aggregation extends across inner units (one denied unit denies the
  whole `(may-i ...)`).
- Recursion depth and `:via` fact propagation survive the refactor.
- Trace output for `(may-i ...)` over a compound input shows the per-unit
  evaluation, not a single opaque rollup.

**Non-Goals:**
- Changing the rule grammar (no new forms).
- Recursing into runtime-dynamic strings (`eval "$X"` — the inner is unknown,
  stays `:ask`).
- Recursing into arg values that aren't intended as commands (no
  rule-driven argument-shape inference here; the existing
  `(positional ... . (may-i *))` form still controls when recursion happens).
- Solving the broken `(positional "-c" . (may-i *))` rule shape (separate
  problem — `-c` is stripped by `positional_args`). Tracked separately.

## Decisions

### 1. Shared recursive evaluator, called from both paths

Extract the body of `evaluate_command_inner` into a function that takes:
- `input: &str`
- `config`, `facts`, `fold`
- `depth: usize`, `limit: usize`

Both top-level evaluation and `Effect::MayI` call it. The existing
`evaluate_command_inner` becomes a thin wrapper that starts with `depth=0`.

`Effect::MayI` joins its `args` into a single string and calls the shared
function with `depth+1` and a facts table extended with `:via`.

**Alternative**: Keep the two paths separate and duplicate the decompose
logic into `Effect::MayI`. Rejected — creates two places that must stay in sync.

### 2. `:via` fact is injected at the recursion boundary

The current `Effect::MayI` injects `:via` on the inner context before
calling `Evaluator::evaluate`. The shared evaluator must preserve this: the
recursion accepts an optional `via` argument that the caller (`Effect::MayI`)
sets to the wrapper command name. Top-level callers pass `None`.

### 3. Depth limit is per-recursion-call, not per-unit

`evaluate_command_inner` already increments depth when recursing into
`EmbeddedCommand` substitutions. The MayI recursion should likewise count as
one depth step regardless of how many `EvalUnit`s the inner command
produces — otherwise a wrapper with a long pipeline would trigger the limit
spuriously.

### 4. Worst-case aggregation matches existing behaviour

`Decision` already has an ordering (`Allow < Ask < Deny`). The shared evaluator
takes the max across units. This is unchanged.

### 5. Fold trace shape

`effect_may_i` currently receives a single `(inner_cmd, inner_args, result)`
triple. With compound inner, there is no single `inner_cmd`. Two options:

- **(a)** Pass the original argument string and the aggregate result. The fold
  surfaces "may-i recursion → :decision" as one node, with per-unit detail
  available via the inner fold events that fire during the recursive call.
- **(b)** Pass a `Vec<(EvalUnit, EffectResult)>` so the fold can render each
  inner unit explicitly.

Lean toward **(a)** for the first cut — fold events from the recursive
`evaluate_command_inner` already produce per-unit trace lines. The MayI
wrapper just needs to bracket them.

### 6. Empty-args case

If `(may-i ...)` is reached with no args (e.g. `sudo` alone), current code
returns `effect_may_i_no_match`. Preserve this — the shared evaluator's
"empty command" handling produces `:ask`, but the MayI branch should still
short-circuit before calling it to keep the fold trace clean.

## Risks / Trade-offs

- **Trace verbosity grows.** A `(may-i)` over `bash -c "if … fi"` will now
  emit per-inner-unit trace lines. Users will see more output. Mitigation:
  fold rendering should indent or group inner units under the wrapper.
- **Performance.** Recursing through full parse + decompose for every
  `(may-i)` is more work than `parse_simple_command`. Negligible in practice
  — these inputs are short. No benchmark needed unless a regression appears.
- **Subtle behaviour change for non-compound inner.** Today, a simple inner
  like `sudo echo hi` works via `parse_simple_command`. Under the new path,
  the same input flows through full `parse` + `decompose`, which produces the
  same `EvalUnit::SimpleCommand`. Equivalent end result. Verify via existing
  tests.

## Open Questions

- Should `bash -c "$X"` (dynamic inner) be `:ask` or surface a more
  informative reason? The decompose path already classifies this as
  `EvalUnit::DynamicCommand` — the existing reason ("dynamic command name: …")
  flows through naturally. Probably good as-is.
- Does `extract_inner_command` have any callers outside `Effect::MayI`?
  Check `pub(crate)` references. If yes, those need updating too.

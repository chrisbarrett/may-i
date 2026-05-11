## Context

The engine has multiple near-parallel pieces of code that all "evaluate a
string as a shell command":

1. **`evaluate_command_inner`** (`crates/engine/src/eval/command.rs`) —
   top-level entry point used by `cmd_eval`, `cmd_claude_code_hook`, etc.
   Parses, calls `decompose`, evaluates each `EvalUnit`, aggregates
   strictest, applies parse-error floor. Handles compound input correctly.

2. **`recurse_into_bound_command`** (`crates/engine/src/eval/effects.rs`
   ≈L235) — the recursion path for `Effect::Authorise { binding }`, the
   surface `(authorise #var)`. Calls `parse_simple_command`, falls back to
   "value as command, no args". Does **not** decompose. Compound inner
   commands fall through to the broken fallback.

3. **`recurse_into_inner_command`** (`crates/engine/src/eval/effects.rs`
   ≈L723) — the recursion path for `(parameter NAME (authorise))`
   single-token captures. Same `parse_simple_command` + fallback. Same bug.

4. **`evaluate_tail_authorise_fold`** (`crates/engine/src/eval/effects.rs`
   ≈L412) — the recursion path for `ArgPattern::Tail` /
   `(tail (authorise))`. Uses `extract_inner_command` (which wraps
   `parse_simple_command`). Same bug.

The asymmetry is the bug. Three recursion sites with the same shortcoming;
each duplicates parse-and-recurse logic that already exists, correctly, at
the top level. The fix is to collapse all three onto the top-level path
(or share a helper).

## Goals / Non-Goals

**Goals:**
- Every `(authorise …)` recursion correctly evaluates any shell command the
  top-level evaluator can evaluate.
- Strictest-wins aggregation extends across inner units (one denied unit
  denies the whole `(authorise …)`).
- Recursion depth and `:via` fact propagation survive the refactor.
- Trace output for `(authorise …)` over a compound input shows the
  per-unit evaluation, not a single opaque rollup.
- All three recursion sites converge on one helper. No new place where
  compound inner is silently mis-handled.

**Non-Goals:**
- Changing the rule grammar (no new surface forms).
- Recursing into runtime-dynamic strings (`eval "$X"` — the inner is
  unknown, stays `:ask`).
- Recursing into arg values that aren't intended as commands (the
  parser-binding declarations still control when recursion happens).
- Reworking the `via-fact-builtin` spec to current vocabulary — handled by
  a separate hygiene change.

## Decisions

### 1. Shared recursive evaluator, called from all four paths

Extract the body of `evaluate_command_inner` into a function that takes:
- `input: &str`
- `config`, `facts`, `fold`
- `depth: usize`, `limit: usize`
- `outer_offset: usize`
- `via: Option<&str>` (NEW — wrapper command name to push onto `:via`)

The top-level entry point (`evaluate_command_with_fold`) calls it with
`via = None`. Each of the three `(authorise …)` sites calls it with
`via = Some(ctx.command)` and `depth = ctx.recursion_depth + 1`.

**Alternative**: Keep paths separate and duplicate decompose logic into
each site. Rejected — three places that must stay in sync, and the bug
this change fixes is precisely the cost of that duplication.

### 2. `:via` push happens inside the shared evaluator

Today each recursion site calls `inner_facts.insert_scalar(:via, …)`
before invoking the inner evaluator. After this change, the shared
evaluator accepts `via: Option<&str>` and performs the insert itself
when present. This keeps the contract in one place and means future
recursion sites can't forget it.

### 3. Depth limit is per-recursion-call, not per-unit

`evaluate_command_inner` already increments depth when recursing into
`EvalUnit::EmbeddedCommand` substitutions. Each `(authorise …)`
recursion likewise counts as one depth step regardless of how many
`EvalUnit`s the inner command produces — otherwise a wrapper around a
long pipeline would trigger the limit spuriously.

### 4. Strictest-wins aggregation matches existing top-level behaviour

`Decision` has an ordering (`Allow < Ask < Deny`). The shared evaluator
takes the max across units. This is unchanged from the current
top-level path. The `order-independent-rules` change already wired
strictest-wins at the per-program layer; this change extends it
through the recursion boundary by composition (no new aggregation
semantics).

### 5. Trace shape

The three recursion sites currently surface the inner decision via
either `effect_terminal` (in `recurse_into_bound_command`) or
`effect_arg_continuation` (in the other two). The shared evaluator
emits per-unit fold events for each inner `EvalUnit` it visits, so the
trace already gets per-unit detail "for free". Each site continues to
wrap that with its own outer fold event (terminal or arg-continuation)
so the existing trace shape is preserved.

If trace verbosity becomes a concern, indent/group the inner events
under the wrapper node — display concern, not engine concern.

### 6. Empty-value short-circuit

`(authorise #var)` is already specified to be a no-match when the
binding is unbound or empty (`parser-bindings` spec). The shared
evaluator's "empty command" handling produces `:ask`, which is wrong
for this contract. Each site keeps its existing empty-value guard and
short-circuits before calling the shared evaluator.

### 7. `extract_inner_command` removal

Once the tail path uses the shared evaluator, `extract_inner_command`
has no callers. Delete it. `parse_simple_command` itself remains — it's
still useful elsewhere (e.g., display, migration) — but it's removed
from the recursion path.

## Risks / Trade-offs

- **Trace verbosity grows.** `(authorise #cmd)` over `bash -c "if … fi"`
  will now emit per-inner-unit trace lines. Users will see more output.
  Mitigation: rendering can indent or group inner units under the wrapper.
- **Performance.** Recursing through full parse + decompose for every
  `(authorise …)` is more work than `parse_simple_command`. Negligible —
  these inputs are short. No benchmark needed unless a regression appears.
- **Subtle behaviour change for non-compound inner.** Today, a simple
  inner like `echo hi` works via `parse_simple_command`. Under the new
  path, the same input flows through full `parse` + `decompose`, which
  produces a single `EvalUnit::SimpleCommand`. Equivalent end result.
  Verify via existing tests.
- **Three sites, one helper — but each site keeps its own outer fold
  event.** Mechanical risk that one site forgets to bracket the
  recursion. Mitigated by integration tests covering each site's trace
  shape.

## Open Questions

- Should `bash -c "$X"` (dynamic inner) be `:ask` or surface a more
  informative reason? The decompose path already classifies this as
  `EvalUnit::DynamicCommand` — the existing reason ("dynamic command
  name: …") flows through naturally. Probably good as-is.
- The `via-fact-builtin` live spec still uses retired vocabulary
  (`(may-i *)`, `(effect :deny)`). Out of scope here; tracked by a
  separate spec-hygiene change.

## Why

`may-i` already recognises a call to a **script-local function** as an internal
call (`:allow`, never `No rule for command …`) when the function is live at the
call site. But that recognition stops at the command-substitution boundary. A
substitution such as `dest=$(resolve)` is sliced out as its own `EmbeddedCommand`
and re-evaluated from an isolated source string (`"resolve"`) that carries none
of the surrounding function definitions — so the call reads as an unknown
external program and asks. `x=$(helper)` (assigning a helper's output) is at
least as idiomatic as calling the helper bare, so the spurious prompt lands on
ordinary code. A spurious ask on idiomatic bash trains users to reflex-approve,
the exact failure mode `may-i` exists to prevent.

## What Changes

- Carry the set of **functions live at a substitution's site** into the embedded
  evaluation, so a call to a script-local function inside `$(…)` / backticks /
  process substitution is recognised as internal exactly as the same bare call
  at that site would be.
- The inherited set is **position-aware** — the functions provably live at the
  substitution's byte offset, reusing the existing Tier-1/Tier-2 liveness
  analysis. A forward-referenced function (`x=$(resolve); resolve() { … }`) is
  **not** recognised, preserving soundness (never under-asks).
- Recognition **propagates recursively** through nested substitutions
  (`x=$(outer $(inner))`): each level seeds its inner evaluation with
  `inherited ∪ locally-live-here`, so nesting works without a depth cap.
- The inherited set is computed **eagerly** in `decompose` (the only place that
  holds the outer AST) and carried as an additive field on
  `EvalUnit::EmbeddedCommand`. The default empty set reproduces today's
  behaviour exactly.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: extend the script-local-function requirement
  so recognition crosses the command-substitution boundary using the liveness
  in force at the substitution's site, with the governing invariant that a call
  inside a substitution receives the same internal/external classification it
  would receive as a bare call at that site.

## Impact

- `crates/engine/src/eval/decompose.rs` — add an `inherited_fns` field to
  `EvalUnit::EmbeddedCommand`; thread an inherited-live-name set into
  `decompose`, seed the liveness analysis with it, and compute each
  substitution's carried set as `inherited ∪ locally-established-at-span`.
- `crates/engine/src/eval/command.rs` — pass the carried set through
  `eval_units` into the recursive embedded evaluation (`depth + 1`) so it seeds
  the inner `decompose`; recursion propagates it for nested substitutions.
- Tests: `crates/engine` — a metamorphic proptest asserting substitution-site
  classification equals bare-call-at-site classification, plus the spec
  scenarios (recognised in subst, forward-ref external, nested, body-site).
- No DSL, config, or trust-hash surface change; no migration (the field is on an
  internal AST type, not user config). Out of scope: the substitution-origin
  label defect (`outer_command_name` cross-attribution) — tracked as a separate
  change.

## Why

When a `cond` branch matches and short-circuits evaluation, all subsequent
unevaluated branches render individually as `(… …)` pairs. This creates visual
noise — four skipped branches produce four identical placeholder lines that add
no information. A single `…` after the matching branch communicates the same
thing more concisely.

## What Changes

- After a matching `cond` branch, collapse all trailing skipped branches (and
  skipped fallback) into a single `…` ellipsis node.
- Branches *before* the match that were evaluated (predicate tested → no) still
  render normally with their trace output.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `trace-system`: Cond trace output changes from per-branch ellipsis to a single
  trailing ellipsis after short-circuit.

## Impact

- `src/annotation.rs`: `TracingFold::effect_cond` — rendering logic for cond
  branches.
- Existing trace snapshot tests will need updating to reflect collapsed output.

## Why

The Facts bucket holds 4 specs: `fact-system`, `via-fact-builtin`,
`fact-predicates-in-args`, `v2-expr-fact-binding` (handled in
`consolidate-parsing-specs`). `fact-system` describes the general
fact-storage and query model; `via-fact-builtin` describes one
specific automatic fact (`:via`) that the `(authorise …)` recursion
pushes. The latter is small (2 reqs, 45 lines) and reads naturally as a
sub-section of the parent.

`fact-system`'s name carries a redundant *system* suffix; the
user-vocabulary noun is *Fact*. We rename to `facts` while folding
`via-fact-builtin` in.

`fact-predicates-in-args` is contributor-only (3 reqs, 56 lines, declares
its audience) and stays standalone — *Predicate* in its name is allowed
under the spec-name exemption added in `spec-hygiene`.

## What Changes

- **Rename `fact-system` → `facts`**: directory rename. The 4 existing
  requirements travel unchanged.
- **Fold `via-fact-builtin` → `facts`**: 2 requirements about the `:via`
  automatic fact and the policy that no other fact is automatically
  pushed.
- **Keep `fact-predicates-in-args` standalone** (contributor-only).

Net 3 → 2 facts specs (excluding the parsing-side `v2-expr-fact-binding`
which is handled separately).

## Capabilities

### New Capabilities

- `facts` — created at archive by renaming `fact-system` and absorbing
  `via-fact-builtin`.

### Modified Capabilities

- (none — rename + fold expressed as new + removed)

### Removed Capabilities

- `fact-system` — renamed to `facts`. Directory removed.
- `via-fact-builtin` — folded into `facts`. Directory removed.

## Spec-delta convention

Same as the other consolidation changes. Source-spec deltas list
`## REMOVED Requirements` as bullets; target-spec deltas list `## ADDED
Requirements` by name; the apply step copies bodies verbatim.

## Impact

- `openspec/specs/facts/spec.md` — newly created. Receives 4 from
  `fact-system`, 2 from `via-fact-builtin`. Total 6 requirements.
- 2 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes. Cross-references updated in `tasks.md`.

## Why

The Tracing-and-Output bucket holds 6 specs: `trace-system`,
`human-evaluation-trace`, `pretty-printing`, `var-trace-breakout`,
`unified-renderer`, and `trust-block-context` (handled in
`consolidate-trust-specs`). Two of the six (`unified-renderer` 1 req,
`var-trace-breakout` 3 reqs) are sub-spec stubs that describe rendering
mechanics already governed at a higher level by `trace-system`.

This change folds the two stubs into `trace-system`. The vocabulary-driven
renames `trace-system` → `traces` and `human-evaluation-trace` →
`decision-trace` are deferred to `rename-specs-to-vocab`.

Net 5 → 3 tracing specs (after this change runs alongside
`consolidate-trust-specs`).

## What Changes

- **Fold `unified-renderer` → `trace-system`** (contributor-only): 1
  requirement (*Heading and label widths use visible character width*)
  about rendering mechanics that live alongside the trace surface they
  serve.
- **Fold `var-trace-breakout` → `trace-system`**: 3 requirements about
  breakout sections that show define-body matches inline.
- **Keep standalone**: `human-evaluation-trace` (large, focused),
  `pretty-printing` (large, distinct).

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `trace-system` — ABSORBS `unified-renderer` and `var-trace-breakout`.
  4 requirements added to its existing 18.

### Removed Capabilities

- `unified-renderer` — folded into `trace-system`. Directory removed at
  archive.
- `var-trace-breakout` — folded into `trace-system`. Directory removed
  at archive.

## Spec-delta convention

Source-spec deltas list `## REMOVED Requirements` as `### Requirement:
NAME` blocks with **Reason** and **Migration** lines. Target-spec deltas
list `## ADDED Requirements` with full body and `#### Scenario:` children
copied verbatim from the source files.

## Impact

- `openspec/specs/trace-system/spec.md` — receives 1 from
  `unified-renderer` and 3 from `var-trace-breakout`.
- 2 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes. The renames `trace-system` → `traces`
and `human-evaluation-trace` → `decision-trace` (vocab alignment per
`spec-conventions`) are deferred to `rename-specs-to-vocab`.

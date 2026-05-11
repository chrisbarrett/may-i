## Why

The Rules-and-Evaluation bucket holds 6–7 specs depending on how it's
counted: `rule-evaluation`, `rule-combination`, `eval-segment-decisions`,
`eval-stdin` (CLI-leaning, handled in `consolidate-cli-hooks`),
`evaluator-error-handling`, `expr-combinator-matching` (handled in
`consolidate-parsing-specs`), plus `partial-pattern-matching` (also
parsing). Two of the rules-bucket members are sub-spec stubs
(`evaluator-error-handling` 1 req; `eval-segment-decisions` 4 reqs about
how decisions surface per-segment) that read more cleanly inside
`rule-evaluation` itself.

This change folds the two stubs into `rule-evaluation`. The `rule-evaluation`
name itself reads as a candidate for rename to `rule-decisions` (the
user-vocabulary noun is *Decision*), but that rename is deferred to a
dedicated `rename-specs-to-vocab` change that handles every
vocabulary-misaligned spec name in one pass.

Net 4 → 2 rules specs (after this change runs alongside the parsing and
CLI consolidations).

## What Changes

- **Fold `evaluator-error-handling` → `rule-evaluation`** (contributor
  detail): 1 requirement (*Check evaluation propagates errors*) about
  error propagation through the eval path.
- **Fold `eval-segment-decisions` → `rule-evaluation`**: 4 requirements
  about how the eval result exposes per-segment decisions, byte-range
  semantics, display behaviour, and aggregate stability.
- **Keep `rule-combination` standalone** (112 lines, 4 reqs — sized;
  combiner semantics is a distinct surface).

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `rule-evaluation` — ABSORBS `evaluator-error-handling` and
  `eval-segment-decisions`. 5 requirements added to its existing 6.

### Removed Capabilities

- `evaluator-error-handling` — folded into `rule-evaluation`. Directory
  removed at archive.
- `eval-segment-decisions` — folded into `rule-evaluation`. Directory
  removed at archive.

## Spec-delta convention

Source-spec deltas list `## REMOVED Requirements` as `### Requirement:
NAME` blocks with **Reason** and **Migration** lines. Target-spec deltas
list `## ADDED Requirements` with full body and `#### Scenario:` children
copied verbatim from the source files.

## Impact

- `openspec/specs/rule-evaluation/spec.md` — receives 1 requirement from
  `evaluator-error-handling` and 4 from `eval-segment-decisions`. Total
  11 requirements after the change archives.
- 2 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes.

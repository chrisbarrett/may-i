## Why

The May 2026 spec audit identified three files under `openspec/specs/` that are no longer specifications of current behaviour:

- `arg-tokenisation` describes a retired DSL surface (`:style` PLIST, `:long-prefix`, `:pun` keyword, `(may-i *)` recursion verb). The current syntax is in `dsl-form-list-syntax`. The two contradict each other directly: a reader trying to learn the DSL gets opposite advice depending on which they read first.
- `config-load-surface` documents a one-shot internal refactor (removing a `LoadResult` wrapper) that has already landed. Its requirements describe code shape, not behaviour, and its Purpose is the literal stub `TBD - created by archiving change deepen-loaded-config. Update Purpose after archive.`
- `review-followup` is a task checklist ("all pre-release review tasks are completed") in delta-spec format. It is a tracker, not a behavioural specification.

`spec-conventions` requires that stable specs document behaviour, have written (non-TBD) purposes, and not contradict other specs. These three fail those tests structurally — not by drift, but by being the wrong artefacts in the wrong place. Removal is the right action.

## What Changes

- **BREAKING (spec layout)** Remove `openspec/specs/arg-tokenisation/`. The canonical parsing DSL spec is `dsl-form-list-syntax`.
- **BREAKING (spec layout)** Remove `openspec/specs/config-load-surface/`. The structural invariant it documents (no `LoadResult` wrapper) is now an unstated convention enforced by code review.
- **BREAKING (spec layout)** Remove `openspec/specs/review-followup/`. The original task list is preserved in the archived changes that produced it.

No code changes. No behaviour changes. No CLI, config, or wire-format changes.

This is the first of several planned hygiene passes. Subsequent passes will handle (a) format normalisation of the 22 remaining delta-format stable specs, (b) writing Purposes for the 17 specs that still carry the `TBD` stub, and (c) folding the 13 thin specs identified in the audit. Those passes are sequenced after the in-flight `parser-named-bindings` and `order-independent-rules` changes land, since both will rewrite specs in those buckets.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

(none)

### Removed Capabilities

- `arg-tokenisation` — superseded by `dsl-form-list-syntax`
- `config-load-surface` — documents a one-shot refactor that has landed; nothing to enforce
- `review-followup` — task list, not behaviour

## Impact

- `openspec/specs/arg-tokenisation/` — deleted
- `openspec/specs/config-load-surface/` — deleted
- `openspec/specs/review-followup/` — deleted
- No source files affected. No tests affected. No CLI surface affected.

## Non-Goals

- Touching the 22 specs with delta-style top-level headings (format normalisation).
- Filling the 17 `TBD` Purpose stubs (separate hygiene pass).
- Folding thin specs into parents (depends on in-flight changes landing first).
- Reviewing trust-relevance declarations across the spec set (separate work, follows `order-independent-rules`).

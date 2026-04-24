## Context

`TracingFold::effect_cond` (annotation.rs) iterates over each branch and renders
skipped branches as individual `(… …)` clause pairs. After a matching branch
short-circuits evaluation, the evaluator marks all subsequent branches as
`(ChildResult::Skipped, ChildResult::Skipped)`. These appear as repeated
identical placeholder lines in the trace — pure noise once we know evaluation
stopped.

## Goals / Non-Goals

**Goals:**

- Collapse all trailing fully-skipped cond branches (and skipped fallback) into
  a single dimmed `…` atom.
- Preserve full rendering of branches before the match (predicate evaluated to
  false → show the trace).

**Non-Goals:**

- Changing how the evaluator produces `ChildResult` values — the fold interface
  stays the same.
- Collapsing branches in predicates (`predicate_cond`) — only `effect_cond`.

## Decisions

**Collapse in `effect_cond`, not a post-processing transform.**

The fold method already knows which branches are `Skipped`. Collapsing there is
a 5-line change. A separate transform pass would need to heuristically detect
the pattern after the fact. No reason to add complexity.

**Merge skipped fallback into the single trailing `…`.**

When a branch matched, the fallback is also `Skipped`. Rather than emitting a
separate `…` for the fallback, the single trailing `…` covers both remaining
branches and fallback. One ellipsis = "everything after here was skipped".

**Implementation**: After iterating branches, count trailing `(Skipped, Skipped)`
pairs. If any exist, remove them and push a single `dim(plain_atom("…"))`. Apply
same logic to a `Skipped` fallback when trailing skipped branches exist.

## Risks / Trade-offs

**[Snapshot test churn]** → Small. Only tests with cond short-circuiting need
updating. The new output is strictly shorter.

**[Lost detail for debugging]** → Minimal. The skipped branches contained no
evaluated information — they were all `…` already. Users who need to see the full
rule structure can read the config file directly.

## Context

`evaluate_command_inner` (`crates/engine/src/eval/command.rs`) walks
`EvalUnit`s from `decompose()` and accumulates the strictest decision. The
`EvalUnit` enum (`crates/engine/src/eval/decompose.rs`) carries `command`,
`args`, and `source` strings — but no source spans. `parser::segment()`
(`crates/shell-parser/src/segment.rs`) is a separate, lexer-level pass that
returns byte-ranges for top-level command/operator segments.

`cmd_eval::colorize_segments` calls `parser::segment()`, then calls
`engine::eval::evaluate_command` once per segment, just to colour them. This
is correct but wasteful and couples display to the engine entry-point.

The two granularities (engine `EvalUnit` vs parser `Segment`) overlap but do
not match exactly: `decompose()` walks the AST and produces units for nested
embeds; `segment()` works at the lexer level and stops at top-level
operators. Display only colours top-level segments today.

## Goals / Non-Goals

**Goals:**
- One evaluation pass produces every decision the CLI needs.
- Display becomes a pure function of `(input, EvalResult)`.
- Engine API explicitly carries the information today's display silently
  re-derives.

**Non-Goals:**
- Changing the aggregate `decision` / `reason` for any input.
- Reworking `parser::segment()` semantics or eliminating it (it is also used
  by trust-block detection in the gate / `check_trust_json_block`).
- Exposing per-rule trace data through `segment_decisions` — that remains
  the trace's job.

## Decisions

### Decision: Segments correspond to engine `EvalUnit`s, not lexer `Segment`s
`segment_decisions` mirrors what the engine actually evaluates. Display
adapts (today it can colour at engine granularity rather than parser
granularity, and an embedded `$(...)` becomes its own coloured span — a
bonus, not a regression).

Alternative: align `segment_decisions` with `parser::segment()` ranges by
having the engine map units back to top-level segments. Rejected — that
adds an asymmetric mapping layer with no semantic gain. The engine should
report what it evaluated.

### Decision: Each `EvalUnit` variant gains a `Span`
`EvalUnit::SimpleCommand`, `EmbeddedCommand`, and `DynamicCommand` each
carry a `span: (usize, usize)` referring to byte offsets in the original
input. `decompose()` already walks AST nodes that have spans (from
`shell_parser`); pass them through.

Alternative: a parallel `Vec<Span>` keyed by `EvalUnit` index. Rejected —
shape is fragile, easy to desync.

### Decision: `SegmentDecision` is a small struct, not a tuple
```rust
pub struct SegmentDecision {
    pub start: usize,
    pub end: usize,
    pub decision: Decision,
}
```
Public API; named fields are clearer than `(usize, usize, Decision)`.

### Decision: Embedded segments nest inside their parent
The outer `echo $(rm)` produces a `SegmentDecision` for the whole `echo
$(rm)` range plus an inner one for `rm`. Display iterates top-level
segments; if it wants to highlight nested embeds it can filter by
containment. Today's display ignores nested embeds (they're inside the
parent simple-command segment text), so this preserves behaviour while
making nesting expressible.

### Decision: `EvalResult.segment_decisions` defaults to empty
`EvalResult::new(decision, reason)` constructs an empty
`segment_decisions`. Tests and constructors that don't care continue to
work. Engine population is opt-in by virtue of going through
`evaluate_command_inner`.

## Risks / Trade-offs

- **Risk: byte ranges drift from input when the engine recurses through
  process-substitution `<(...)` or nested embeds.** Mitigation: the spans
  must always reference the *outermost* original input. `decompose()` and
  `evaluate_command_inner` will have to track an offset when stepping into
  embedded sources. Add a unit test for nested-embed offsets.

- **Risk: snapshot tests of CLI output break if display now colours embedded
  segments distinctly.** Mitigation: keep display granularity at top-level
  segments by filtering out nested entries (those whose range is contained
  in another). Snapshots stay byte-identical.

- **Trade-off: `EvalResult` grows by `Vec<SegmentDecision>`.** Trivial
  memory cost; serialises naturally if ever exposed in JSON.

- **Trade-off: spans on `EvalUnit` variants change a struct used by tests.**
  Acceptable churn; engine internal.

## Migration Plan

1. Add `SegmentDecision` and `EvalResult.segment_decisions` (default empty);
   add `Span` to `EvalUnit` variants and to `decompose()` output.
2. Populate `segment_decisions` in `evaluate_command_inner` per unit.
3. Engine unit tests assert each scenario from the spec.
4. CLI: `evaluate_with_colorization` becomes a fold over
   `result.segment_decisions`. Remove the per-segment
   `engine::eval::evaluate_command` call.
5. Snapshot-verify CLI output byte-identical for representative inputs.

Rollback: trivial — `segment_decisions` is additive; CLI can fall back to
the old re-eval path until step 4 lands.

## Open Questions

- Does `decompose()` already retain enough span info from `shell_parser`'s
  AST to emit byte-ranges, or do we need to thread spans through during AST
  walking? Inspect during implementation; if the AST loses spans, fixing
  that is in-scope for this change.
- For nested embedded commands, do we report nested `SegmentDecision`s
  flat (one vector with overlapping ranges) or as a tree? Default flat with
  an invariant that an inner range is always fully contained in a top-level
  range; revisit if display needs the structure.

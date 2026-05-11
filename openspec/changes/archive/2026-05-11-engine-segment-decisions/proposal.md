## Why

`cmd_eval` evaluates a command twice: once via
`engine::eval::evaluate_command_with_fold` for the verdict and trace, then a
second time per top-level segment via `engine::eval::evaluate_command` purely
to colorise each segment in display
(`src/cmd_eval.rs:194-214 colorize_segments`). The engine has already
computed each unit's decision during the first pass; the second pass exists
only because that information is not exposed at the `EvalResult` boundary.

The deletion test on `colorize_segments`: removing it loses the per-segment
colour but the engine still made the decisions. The seam — `EvalResult`
returning a single aggregate verdict — is too narrow for what the caller
needs. Display reaches back into the engine to re-derive state, coupling
display to engine internals (`evaluate_command`).

## What Changes

- **Extend `EvalResult`** with a `segment_decisions: Vec<SegmentDecision>`
  field where each entry is `{ start: usize, end: usize, decision: Decision }`,
  byte-ranges into the original input. The aggregate `decision` and `reason`
  fields stay; `segment_decisions` is additive.
- **Engine populates segments** during the single pass:
  `evaluate_command_inner` already walks `EvalUnit`s; each unit's source span
  is recorded and produces one `SegmentDecision`. Embedded commands and
  process substitutions each get their own entry; their parent simple-command
  span covers the rest. (Display today only colours top-level segments, so
  the engine MAY collapse to top-level segments matching `parser::segment()`
  granularity if the AST carries that information; design decides.)
- **CLI display becomes a pure function** of `(command, EvalResult)`:
  `colorize_segments(command, &result.segment_decisions)`. No second
  evaluation, no `engine::eval::evaluate_command` call from the display path.
- **Hook and JSON modes ignore `segment_decisions`**; they remain
  byte-identical.
- **`EvalUnit::DynamicCommand`** segments report `:ask` (today's behaviour),
  carrying the same span.
- **Removed**: `cmd_eval::colorize_segments`'s second-pass evaluation. The
  function reduces to a fold over `result.segment_decisions`. The
  `colorize_text` helper stays.

## Capabilities

### New Capabilities

- `eval-segment-decisions`: the engine's `EvalResult` carries per-segment
  decisions with byte-ranges, sufficient for display to colourise without
  re-evaluating. This is a public-API guarantee; today display reaches back
  into the engine to recompute, with no spec covering the colour mapping.

### Modified Capabilities

- None.

## Impact

- `crates/engine/src/lib.rs` — `EvalResult` gains
  `segment_decisions: Vec<SegmentDecision>`; new `SegmentDecision` type.
- `crates/engine/src/eval/command.rs` — `evaluate_command_inner` records
  spans alongside per-unit decisions and pushes them onto the result.
- `crates/engine/src/eval/decompose.rs` — `EvalUnit` variants gain a span
  field (or a sibling vector keyed parallel to units) so the command-level
  evaluator can map each unit back to a byte range.
- `crates/shell-parser/src/segment.rs` — possible cross-check: do
  `parser::segment()` ranges align with `EvalUnit` ranges? Spec'd as: when
  segmentation differs (e.g., compound bodies), the engine reports its own
  ranges; display tolerates segments without matching engine entries by
  falling back to `:ask`-coloured neutral.
- `src/cmd_eval.rs` — `evaluate_with_colorization` and `colorize_segments`
  simplified; no second eval call.
- `src/annotation.rs` — unaffected (trace already aggregates per-rule
  results).
- Tests — engine unit tests assert `segment_decisions` content for
  representative inputs (single command, `&&`/`;`/`|` compound, embedded
  `$(...)`, dynamic `$EDITOR`, malformed input). CLI snapshot tests should
  continue to pass byte-identically.

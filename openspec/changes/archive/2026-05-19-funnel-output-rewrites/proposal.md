## Why

Trace rendering currently runs four ordered rewrite passes —
`truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated`,
`distribute_arg_annotations` — scattered between
`src/output/transform.rs` and `src/output/mod.rs`. Order matters but is
implicit: each caller composes the passes by hand. The JSON renderer in
`src/output/json.rs` then walks the same annotated tree a second time,
duplicating shape decisions (which `(or …)` lists get truncated, which
branches are dimmed) instead of consuming a shared, already-prepared
artefact. Adding or reordering a pass means editing several files in
lockstep — the seam between "the rendering pipeline" and "an ad-hoc
sequence of helpers" is too shallow to enforce the ordering contract.

## What Changes

- Introduce a single function inside `crate::output` —
  `trace_to_layout(trace, command, indent, term) -> Layout` (name kept
  to match the existing private helper; visibility narrows to
  module-private and its callers switch to it) — that owns the entire
  ordered rewrite pipeline from trace input to a renderer-ready
  `Layout`. Each rewrite pass becomes a named step inside this
  function; the order is encoded in one place.
- Port the text trace renderer (today: `write_layout(write_trace(…))`)
  to consume the `Layout` produced by `trace_to_layout`. The text path
  becomes "build Layout, then write it" with no in-renderer rewrites.
- Port the JSON trace renderer (`trace_to_json`) to consume the same
  prepared shape rather than re-walking the raw trace and re-applying
  truncation / dimming logic. Where the text renderer needs visual
  information the JSON does not (column geometry, dimming styles), the
  shared layer carries the structural decisions and each renderer
  projects the relevant fields.
- Delete the in-renderer duplication: the rewrite functions in
  `src/output/transform.rs` become private helpers of the new pipeline
  function and lose their direct callers in `render_rule.rs` and
  `mod.rs`. No public re-exports of the individual passes survive.
- **BREAKING (internal):** the rewrite passes are no longer callable
  individually from outside the pipeline function. Pre-1.0, single
  workspace, no external consumer.
- **NOT BREAKING (output bytes):** text trace output and JSON trace
  output SHALL match existing snapshots byte-for-byte. Snapshot
  re-baseline is permitted only where the existing
  [output-rendering](../../specs/output-rendering/spec.md) eval-output
  scenario would already permit it (i.e., no incidental drift).

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `output-rendering`: adds a contributor-internals requirement that the
  trace rewrite pipeline has a single named owner (`trace_to_layout`)
  inside `crate::output`, that no `cmd_*` or non-pipeline output
  submodule invokes the individual rewrite passes, and that the text
  and JSON trace renderers share the prepared `Layout` rather than
  re-deriving structural decisions. This pins the funnel so a future
  refactor cannot quietly re-scatter the passes.

The [traces](../../specs/traces/spec.md) requirements describe the
*content* of the rendered trace (two-column layout, dimming rules,
truncation, fact-evidence compaction). They are unchanged by this
change: the same decisions are taken in the same order; only the
location of the code making them moves.

## Coordination

The parallel change
[deepen-trace-rendering](../deepen-trace-rendering/proposal.md) hides
the `Ann` enum behind a `TraceNode` ADT and migrates several structural
decisions (truncation, dimming, cond-branch collapse, per-line
priority) from the renderer into the trace producer. The two changes
compose:

- `deepen-trace-rendering` decides *what shape the producer/renderer
  seam carries.*
- This change decides *where the renderer-side pipeline lives and how
  text and JSON share it.*

When both land, several of the rewrite passes funnelled here move
upstream into the producer; the named-owner requirement still holds
for any passes that remain on the renderer side (column geometry,
visible-width arithmetic, layout-shape decisions that depend on
terminal width). The requirement is phrased in terms of "renderer-side
rewrite passes" rather than naming the four current passes, so the
contract survives that producer-side migration without conflict.

## Impact

- **Code:** `src/output/mod.rs` (consolidate `trace_to_layout`, remove
  in-place pass orchestration), `src/output/transform.rs` (passes
  become private helpers; remove `pub(super)` orchestrator if it
  becomes redundant), `src/output/render_rule.rs` (remove any
  re-application of passes), `src/output/json.rs` (consume the
  prepared `Layout` instead of re-walking `Doc<Option<Ann>>`).
- **Snapshots:** insta snapshots under `tests/snapshots/` and
  `crates/may-i-output/src/snapshots/` SHOULD be unchanged. Any
  diff requires reviewer sign-off — the change is not licensed to
  drift bytes.
- **External consumers:** none (pre-1.0, single workspace).
- **Build/CI:** `cargo build`, `cargo test`, `cargo tarpaulin`, and
  `prek` hooks run unchanged.

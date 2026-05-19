## Context

`src/output/` is twelve files (3,710 lines total). Three of those files
collude to render one trace:

- `mod.rs` (852 LOC) defines `render_trace`, which calls a private
  `trace_to_layout(entries, command, indent, term) -> Layout` that walks
  `TraceEntry` and assembles `ColRow`s via a `TraceLayoutBuilder`.
- `transform.rs` (992 LOC) exposes `pub(super) prepare_doc_for_text`,
  which composes the four passes inline:
  `dim_unevaluated(truncate_unevaluated(&truncate_matched_anywhere(doc), 2));
  distribute_arg_annotations(&doc)`. Order is encoded in this single
  expression; callers re-derive it if they want different ordering.
- `render_rule.rs` (482 LOC) calls `prepare_doc_for_text` when
  rendering a rule body row inside `TraceLayoutBuilder::on_rule`.

`json.rs` (603 LOC) re-walks the raw `Doc<Option<Ann>>` via
`collect_json_annotations` and `doc_to_json`, applying its own
truncation rules implicitly (it doesn't truncate; it just emits the
full annotation list and accepts a different shape from the text
renderer).

The seam is shallow: the public interface "render a trace" is more or
less a thin wrapper over "apply these four functions in this order, then
write columns". The
[output-rendering](../../specs/output-rendering/spec.md) spec already
treats `crate::output` as the intent surface for `cmd_*` callers — what
is missing is an *internal* contract that says "exactly one function
owns the rewrite pipeline; both renderers consume its output".

## Goals / Non-Goals

**Goals:**

- One named function (`trace_to_layout`) owns the entire ordered
  rewrite pipeline from `TraceEntry` slice to a renderer-ready
  `Layout`. The order of passes is encoded in that function's body, not
  re-derived by callers.
- Text and JSON trace renderers consume the *same* prepared artefact.
  No second walk that re-derives truncation, dimming, or per-line
  placement.
- Existing snapshots remain byte-identical. This is a refactor; output
  bytes are part of the contract being preserved.

**Non-Goals:**

- Carving the rewrite passes out of `src/output/`. They stay where they
  are — the funnel is about *invocation*, not *location*.
- Rewriting the `Ann` / `Doc` types or the producer/renderer seam.
  That is the scope of
  [deepen-trace-rendering](../deepen-trace-rendering/proposal.md). This
  change phrases its requirement in terms of "renderer-side rewrite
  passes" so the funnel survives when several passes migrate upstream.
- Adding a public re-export for `Layout`. The
  [output-rendering](../../specs/output-rendering/spec.md) requirement
  that `crate::output` does not re-export `Layout` primitives stands.
  The funnel lives entirely behind `render_trace` /
  `render_eval_result` / `trace_to_json`.
- Removing `transform.rs` or merging it into `mod.rs`. The passes can
  live in their own file; the funnel just becomes their only caller.

## Decisions

### One function owns the rewrite pipeline; passes are private helpers

`trace_to_layout` in `src/output/mod.rs` (today: returns `Layout` for
the text path) becomes the sole orchestrator. Each rewrite pass that
operates on `Doc<Option<Ann>>` becomes a `fn` called from
`trace_to_layout` (directly or via the existing `TraceLayoutBuilder`),
with a docstring naming its position in the pipeline. The current
`prepare_doc_for_text` helper either becomes a private inline step of
`trace_to_layout` or stays as a named sub-step — either is fine as long
as no other function in `src/output/` invokes the individual passes.

**Alternative considered: a pipeline struct with `Vec<Box<dyn Pass>>`**
— overengineered for four passes that have lived in the same order for
multiple releases. Dynamic-dispatch over a four-element fixed sequence
adds indirection without solving the actual problem (where is the
pipeline defined and who calls it?). Rejected.

**Alternative considered: keep `prepare_doc_for_text` as the funnel,
just narrow its visibility and route JSON through it too** — viable
in principle, but `prepare_doc_for_text` is named for the text path
and operates on a single `Doc`. The pipeline that callers actually
need spans `[TraceEntry] → Layout`, not `Doc → Doc`. Promoting
`trace_to_layout` to the contract surface keeps the seam aligned with
what consumers ask for. Rejected as the funnel; kept as a private
sub-step.

### JSON renderer consumes the same prepared `Layout`, not a parallel walk

`trace_to_json` today walks `Doc<Option<Ann>>` directly and emits an
annotation array per rule. After this change, `trace_to_json` consumes
the structurally-prepared form that `trace_to_layout` already built —
either by sharing an intermediate "prepared trace" representation that
both renderers project from, or by serialising directly from `Layout`
where the JSON shape can be derived from layout nodes.

The exact intermediate is an implementation detail of the funnel
function. Two viable shapes:

1. **Shared prepared tree.** `trace_to_layout` internally builds a
   `PreparedTrace` (sequence of prepared rule entries, each carrying
   the dimmed/truncated `Doc` plus pre-decided annotation placement)
   and projects it to `Layout` for the text renderer. `trace_to_json`
   takes the same `PreparedTrace` and projects to JSON. The funnel
   exports a small `prepare_trace` function used by both renderers.
2. **Layout is the intermediate.** `trace_to_layout` returns `Layout`;
   `trace_to_json` walks `Layout` nodes (which carry the structural
   information JSON needs). Simpler but requires `Layout` nodes to
   carry annotation evidence in a JSON-recoverable form.

Shape 1 is more honest about the two renderers needing slightly
different projections; shape 2 collapses the seam further but risks
contorting `Layout` to carry JSON-only metadata. Implementation chooses
shape 1 unless `Layout` can carry the JSON evidence cleanly without
distortion. Either way, the externally-visible contract is the same:
*neither renderer applies a rewrite pass on its own*.

**Alternative considered: keep `trace_to_json` walking raw
`Doc<Option<Ann>>` and accept the duplication** — rejected. The
duplication is the diagnosis; preserving it defeats the change.

### Spec requirement targets `output-rendering`, not `traces`

The [traces](../../specs/traces/spec.md) spec describes *what* is
rendered (which branches dimmed, which lists truncated, where
annotations land). Those contracts are unchanged. The new requirement
is about *where the rewrite code lives* — a contributor-internals
constraint on `crate::output`'s internal shape, which is the existing
audience of [output-rendering](../../specs/output-rendering/spec.md).
Requirement goes there.

**Alternative considered: a new `trace-rendering-pipeline` capability**
— rejected for failing the "<2 requirements or <40 lines → fold into
parent" rule in `.claude/rules/openspec-specs.md`. A single
internals requirement belongs in the existing `output-rendering`
spec.

### Coordination with `deepen-trace-rendering`

The parallel change moves several passes upstream into the producer.
This change's requirement is worded as "renderer-side rewrite passes
applied to the trace input SHALL be invoked through a single
pipeline function". When `deepen-trace-rendering` lands, fewer
passes remain renderer-side (in the limit, none — the producer hands
a fully-prepared `TraceNode` tree). The funnel requirement is still
satisfied: zero passes is one pipeline (vacuously); any future
renderer-side pass joins the same funnel.

The two changes touch the same spec (`output-rendering`). Both add new
requirements; neither modifies the others'. They compose cleanly as
separate `### Requirement:` blocks under `## ADDED Requirements`.

## Risks / Trade-offs

- **[Risk]** Snapshot drift during refactor — re-ordering the
  intermediate representation could change ANSI escape ordering or
  whitespace. **Mitigation:** every step preserves
  `cargo test` (insta) green; any byte change is investigated, not
  blessed.

- **[Risk]** The JSON renderer historically emits a flat annotation
  list per rule (`collect_json_annotations`); switching to a
  `Layout`-derived walk could change field ordering or include
  annotations from previously-dimmed subtrees. **Mitigation:** the
  existing `Dimmed nodes produce no right-column annotations`
  requirement in `traces` already governs the text side; the JSON
  port preserves the same dimming filter explicitly. Snapshot tests
  for `trace_to_json_*` in `src/output/json.rs` catch any shape drift.

- **[Risk]** Conflict with the parallel `deepen-trace-rendering`
  change — both modify `src/output/mod.rs` and `json.rs`.
  **Mitigation:** land this change first (smaller diff, narrower
  scope); the deepening change rebases its `TraceNode` migration on
  top of the already-funnelled pipeline, which has fewer call sites
  to update.

- **[Risk]** A reader of `transform.rs` no longer sees the pipeline at
  the top of the file. **Mitigation:** `prepare_doc_for_text` (or its
  successor) gets a docstring pointing to `trace_to_layout` as the
  sole caller; `trace_to_layout` lists the ordered steps in its own
  docstring.

## Migration Plan

Single commit. No user-facing migration (no DSL change, no trust-hash
change, no config-syntax change). Snapshot diff expected to be empty;
any non-empty diff triggers review.

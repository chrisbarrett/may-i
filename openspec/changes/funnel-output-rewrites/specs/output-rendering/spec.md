## ADDED Requirements

### Requirement: Trace rewrite pipeline has a single named owner

A single function inside `crate::output` SHALL own the ordered rewrite pipeline that converts a `TraceEntry` slice into the renderer-ready `Layout` consumed by `render_trace`. That function (today named `trace_to_layout`) SHALL be the only call site of any renderer-side rewrite pass applied to trace input — including truncation of matched `(anywhere …)` lists, truncation of unevaluated children, dimming of unevaluated branches, and distribution of argument annotations across rule lines. No other function in `src/output/` and no `cmd_*` module SHALL invoke an individual rewrite pass directly.

#### Scenario: Pipeline is callable from exactly one site

- **WHEN** scanning `src/output/` and `src/cmd_*.rs` for direct calls to the renderer-side rewrite-pass functions (the truncation, dimming, and annotation-distribution helpers that today live in `src/output/transform.rs`)
- **THEN** the only call site is the body of the single pipeline function (today `trace_to_layout`) or a private helper that function delegates to
- **AND** no `cmd_*` module appears in the call-site list

#### Scenario: Pipeline function documents the ordered steps

- **WHEN** reading the docstring of the pipeline function
- **THEN** it names each rewrite step in the order applied, so a reader can identify the pipeline contract without cross-referencing other files

#### Scenario: Adding a renderer-side pass adds one call site

- **WHEN** a future contributor introduces a new renderer-side rewrite pass over the trace input
- **THEN** the pass is invoked from the single pipeline function and from nowhere else, preserving the property in the first scenario

### Requirement: Text and JSON trace renderers share the prepared shape

The text trace renderer (`render_trace` / `write_trace`) and the JSON trace renderer (`trace_to_json`) SHALL consume the structurally-prepared trace produced by the pipeline function defined above. Neither renderer SHALL re-apply the truncation, dimming, or annotation-distribution decisions made inside the pipeline; structural decisions are taken once, and each renderer projects the prepared form to its output bytes. The exact shape of the shared prepared artefact is an internal implementation detail of `crate::output` and is not part of the module's public surface.

#### Scenario: JSON renderer does not duplicate rewrite logic

- **WHEN** scanning `src/output/json.rs` for calls to the renderer-side rewrite-pass functions
- **THEN** zero matches are found
- **AND** the JSON renderer's input is the prepared artefact produced by the pipeline function, not the raw `TraceEntry::Rule` doc

#### Scenario: Text renderer does not duplicate rewrite logic

- **WHEN** scanning `src/output/mod.rs` and `src/output/render_rule.rs` for calls to the renderer-side rewrite-pass functions outside the pipeline function's body
- **THEN** zero matches are found

#### Scenario: Snapshot output bytes preserved

- **WHEN** the snapshot integration tests under `tests/` and the per-module snapshots in `src/output/` run
- **THEN** the rendered text trace bytes and the JSON trace bytes match the existing snapshots, modulo any drift already permitted by the `Eval output bytes unchanged` and `Check output bytes unchanged` scenarios in this spec

---
audience: contributor
bucket: tracing-and-output
---
# output-rendering Specification

## Purpose

Contributor-only. The `crate::output` module's public surface — what `cmd_*` modules may use to render eval results, check failures, traces, and advisories. Hides `may_i_layout::Layout` primitives behind intent-level operations so CLI subcommands describe *what* they want shown, not *how* it is laid out. The top-level intent operations are `render_eval_outcome` (dispatches a closure-produced `EvalOutcome` to its text or JSON shape) and `render_trust_block` (serialises a `TrustBlock` in the response shape dictated by an `InvocationMode`); both are reachable only through `CommandPipeline::run`. See `traces`, `pretty-printing`, and `trust-advisory-boxes` for the rendered formats themselves.

## Requirements

### Requirement: Output module exposes per-subcommand builders, hides Layout primitives and leaf renderers

The `crate::output` module SHALL expose, as its rendering surface, one builder type per subcommand that emits text output: `CheckOutput`, `EvalOutput`, and `TrustListing`. Each builder takes a small intent payload (typed fields, no `Layout` values) and a writer-plus-terminal pair on its `render` method, and emits the complete output for its subcommand in one call.

The module SHALL NOT re-export `may_i_layout::Layout` or its construction primitives (`ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory`).

The module SHALL NOT publicly re-export single-purpose leaf renderers that a builder now owns: `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory`. These SHALL be `pub(crate)` and reachable only through a builder.

The following items remain publicly re-exported from `crate::output`:

- `Terminal`, `write_layout`, `strip_ansi` — the renderer protocol surface.
- `shorten_home` — a path-display utility with multiple unrelated callers.
- `trace_to_json`, `render_check_results_json` — JSON intent operations consumed by both stdout and hook-response paths.
- `colorize_decision_keyword`, `format_flags_mode` — small text helpers reused outside trace/check rendering.

#### Scenario: Builders are the only text-output surface

- **WHEN** a subcommand in `src/cmd_*.rs` writes text output (non-JSON) for the user
- **THEN** it constructs exactly one of `CheckOutput`, `EvalOutput`, or `TrustListing` and calls its `.render(writer, &terminal)` method, without invoking any private leaf renderer

#### Scenario: Layout primitives not in the output module surface

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** none of `Layout`, `ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory` appear

#### Scenario: Demoted leaf renderers are crate-private

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, and `render_wrapper_boundary_advisory` SHALL NOT appear

### Requirement: cmd modules do not assemble Layout values or script render sequences

No `cmd_*` module SHALL construct `Layout::Stack`, `Layout::Columns`, `Layout::Indent`, `Layout::HRule`, or any other `Layout` variant directly, nor build `ColRow` / `ColItem` / `HRuleLabel` values. No `cmd_*` module SHALL invoke more than one rendering call against `crate::output` for a single text-output stream — the sequencing of prelude advisories, body, footer, and any decorative separators SHALL live inside the per-subcommand builder.

#### Scenario: No raw Layout construction in cmd modules

- **WHEN** scanning `src/cmd_*.rs` and `src/main.rs`
- **THEN** zero references to `Layout::`, `ColRow::`, `ColItem::`, or `HRuleLabel` constructors appear

#### Scenario: Single render call per text-output subcommand

- **WHEN** `cmd_check`, `cmd_eval`, or `cmd_trust` produces text output
- **THEN** the subcommand makes exactly one `.render(writer, &terminal)` call against its respective builder

### Requirement: Builders own prelude and trust-warning sequencing

Each per-subcommand builder SHALL emit the prelude advisories (migration note, trust-store integrity) and the trust-warning advisory at the canonical points in its rendering sequence, drawing on `CommandPipeline` state. Subcommands SHALL NOT call `pipeline.render_prelude_advisories()` or `pipeline.render_trust_warning()` directly when a builder will follow; the builder is the single point of emission.

#### Scenario: cmd_check delegates prelude emission to CheckOutput

- **WHEN** `cmd_check` constructs a `CheckOutput` for an invocation that has a trust-store integrity advisory
- **THEN** the integrity advisory appears in the rendered output without `cmd_check` calling `pipeline.render_prelude_advisories()` itself

### Requirement: Rendered output bytes are unchanged

The body bytes emitted by `cmd_check`, `cmd_eval`, and `cmd_trust` SHALL be byte-for-byte identical to today's output for every input covered by existing snapshot tests (`src/output/snapshots/`, `crates/may-i-output/src/snapshots/`, and integration tests under `tests/`).

#### Scenario: Eval output snapshots remain green

- **WHEN** the snapshot tests for `cmd_eval` run against the existing fixture set
- **THEN** stdout and stderr match the stored snapshots byte-for-byte

#### Scenario: Check output snapshots remain green

- **WHEN** the snapshot tests for `cmd_check` run
- **THEN** stdout and stderr match the stored snapshots byte-for-byte

#### Scenario: Trust listing snapshots remain green

- **WHEN** the snapshot tests for `cmd_trust` list mode run
- **THEN** stdout matches the stored snapshots byte-for-byte

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

### Requirement: Trace renderers consume an opaque TraceNode tree

The trace-rendering paths in `crate::output` (the text path through `transform`, `render_rule`, and `mod`; and the JSON path through `json`) SHALL consume an opaque `TraceNode` tree exported by the trace producer and SHALL NOT pattern-match on engine-internal annotation variants. Renderers SHALL NOT import `may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier}` for annotation purposes, and SHALL NOT destructure pattern-internal fields (e.g. `search_tokens`, `arg_set`, regex pattern strings, positional match-mode booleans) from trace nodes.

The `TraceNode` accessor surface SHALL be the only path by which renderers read trace-node content; renderers SHALL access node label, role, evidence, and children via accessors, not by matching on internal enum variants.

#### Scenario: No ArgPattern import in output trace renderers

- **WHEN** scanning `src/output/transform.rs`, `src/output/render_rule.rs`, `src/output/json.rs`, and `src/output/mod.rs` for imports of `may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode, Quantifier}`
- **THEN** zero matches are found

#### Scenario: No Ann variant matches in output trace renderers

- **WHEN** scanning the same files for `Ann::` (the legacy annotation enum) match arms
- **THEN** zero matches are found
- **AND** the `Ann` enum itself is no longer defined in `src/annotation.rs` (or its successor module)

#### Scenario: Renderers reach trace-node content via accessors

- **WHEN** a trace renderer needs a node's label, role, evidence, or children
- **THEN** it reads via the `TraceNode` accessor surface (e.g. `node.role()`, `node.evidence()`, `node.children()`)
- **AND** it does not pattern-match on internal enum variants of `TraceNode` or its sub-types

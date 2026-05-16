## Why

Three shallow seams in the trace-and-output stack force callers to know
implementation details that should live behind the seam:

1. `TraceEntry`/`Ann` carry pre-rendered display strings (e.g. `Parser.flags:
   String = "until <tok>…"`, `FactQuery.observed: Option<Vec<String>>`),
   committing the trace producer to text-renderer presentation choices that
   the JSON renderer then has to swallow.
2. `src/output/transform.rs` exports four `Doc<Option<Ann>>` passes
   (`truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated`,
   `distribute_arg_annotations`) that callers must compose in the right
   order.
3. `trace_to_layout` is a 140-line loop tracking six bespoke state slots
   (`pending_command`, `current_rows`, `last_shown_facts`,
   `pending_parsers`, `first`, `has_segments`); the "pending parser binds
   to next matching command" rule lives only in scattered HashMap
   insert/remove calls.

All three are contributor-internal refactors: rendered bytes do not change,
no requirement-level behaviour shifts. The point is to narrow the
interfaces between trace production, doc-tree preparation, and layout
assembly so that future renderers, transform fusions, or trace-entry
additions are local changes instead of cross-cutting ones.

## What Changes

- Narrow `Ann` and `TraceEntry` to structural data. Move display-only
  stringification (parser flag formatting, observed-value summarisation,
  regex literal quoting, fact-failure prose) into the text renderer.
  The JSON renderer keeps emitting equivalent structured output without
  going through display strings.
- Collapse `src/output/transform.rs`'s four `pub(super)` passes into a
  single private entry point (e.g. `prepare_doc_for_text`). Pass order,
  pass selection, and any future fusion become implementation details.
- Promote the `trace_to_layout` loop's state to a private
  `TraceLayoutBuilder` whose methods (`on_segment_header`, `on_rule`,
  `on_parser`, `on_embedded_command`, `on_default_ask`,
  `on_parse_diagnostics`, `finish`) name the per-entry transitions. The
  "pending parser binds to next matching command" rule becomes a named
  helper.

Rendered output bytes (text and JSON) are unchanged by all three.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `traces`: add a requirement formalising that `Ann` and `TraceEntry`
  fields are structural data only — display-only stringification
  (parser flag formatting, observed-value summarisation, regex literal
  quoting, fact-failure prose) lives in the renderer. Today nothing in
  the spec forbids the producer from baking in display strings; without
  the delta this regression repeats.

The `output-rendering` spec is unchanged. Candidates 2 and 3 are
implementation-only refactors of module-private composition that the
existing requirements already cover structurally (intent-level rendering
operations, no `Layout` construction in `cmd_*`). They land via
tasks.md.

## Impact

- `src/annotation.rs` — `Ann` and `TraceEntry` field shapes (Parser,
  FactQuery, RegexMatch, BindMatch, plus any other variants whose fields
  are pre-rendered text). `TracingFold` fold methods stop calling display
  formatters.
- `src/output/transform.rs` — public-within-`output` surface collapses to
  one entry point; the four pass functions become private helpers.
- `src/output/render_rule.rs`, `src/output/mod.rs` — update call sites for
  the collapsed transform entry point.
- `src/output/mod.rs::trace_to_layout` — replaced by a thin driver over
  `TraceLayoutBuilder`. Text-side stringification (parser flags, observed
  values, fact failure prose, regex literals) moves here from
  `TracingFold`.
- `src/output/json.rs::trace_to_json` — updated to read structural fields
  instead of pre-rendered strings; JSON output bytes unchanged.
- Snapshot tests under `tests/` and `src/snapshots/` MUST stay
  byte-for-byte identical, modulo whitespace already covered by existing
  snapshot machinery.
- No engine-crate changes. No user-facing CLI, DSL, or config changes. No
  trust-relevance.

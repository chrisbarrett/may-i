## Context

The `tracing-and-output` bucket comprises three modules with cross-cutting
seams:

- `src/annotation.rs` (~1900 LOC) — defines `Ann`, `TraceEntry`, and
  `TracingFold`. `TracingFold` runs alongside evaluation in the engine
  fold protocol, producing `(EffectResult, Doc<Option<Ann>>)` per AST
  node and pushing `TraceEntry`s into a sequence.
- `src/output/transform.rs` (~970 LOC) — four `pub(super)` recursive
  passes over `Doc<Option<Ann>>` that prepare the doc for the
  two-column text renderer.
- `src/output/mod.rs::trace_to_layout` (~140 LOC) — converts a
  `Vec<TraceEntry>` into a `may_i_layout::Layout` for the text renderer.

Two consumers of the trace exist today: `output::trace_to_layout` (text)
and `output::json::trace_to_json` (JSON for `--json` mode and hook
introspection). Both read every `TraceEntry`/`Ann` field. The text
renderer's needs have drifted into the producer over time: `Parser.flags`
is now `String = "until <tok>…"`; `FactQuery.observed` is an
`Option<Vec<String>>` already-shaped for the two-column layout; the JSON
renderer accepts these strings as-is because it has no structural
alternative.

The four transform passes in `output/transform.rs` are each independently
documented and tested, but their composition lives in
`render_annotated_rule` and one other call site, both of which know the
correct order.

`trace_to_layout` accumulates six interrelated state slots inline. The
non-obvious invariant — *a `Parser` entry's row is buffered and then
emitted under the next command row whose first token matches the parser's
`command` field* — exists only as `pending_parsers.insert/remove` calls
inside the per-entry match arms.

The change is pre-1.0, contributor-internal, with byte-for-byte snapshot
fidelity as the regression contract.

## Goals / Non-Goals

**Goals:**

- Cut the cross-module coupling between `TracingFold` and text-renderer
  formatting choices by narrowing `Ann`/`TraceEntry` to structural data.
- Collapse `output/transform.rs`'s four-function `pub(super)` surface
  into a single private entry point.
- Replace the `trace_to_layout` inline state machine with a named
  `TraceLayoutBuilder` whose method names match the entry variants and
  whose helpers name the non-obvious rules (notably parser-to-command
  binding).
- Keep text and JSON output bytes identical (snapshot tests as the
  contract).

**Non-Goals:**

- No changes to the engine crate or the `EvalFold` protocol.
- No changes to the user-facing CLI, DSL surface, config, trust, or
  evaluation semantics.
- No changes to which renderers exist. The point is to *enable* future
  renderers and transform fusions, not to add them.
- No splitting of the `output/` module hierarchy beyond what the
  transform-collapse and builder-extraction require.
- No retroactive ADRs unless one falls out of grilling on a load-bearing
  decision.

## Decisions

### 1. `Ann` and `TraceEntry` carry structural data; renderers format

`TracingFold` stops calling display-format helpers when populating
variant fields. Specifically:

- `TraceEntry::Parser.flags: String` becomes a structural enum/struct
  (e.g. `FlagsRendering::Posix | Permute | Until(Vec<String>)`).
- `TraceEntry::Parser.parameter_tokens: Vec<String>` and
  `rest_binding: Option<String>` stay (binding names are already
  structural).
- `Ann::FactQuery.observed: Option<Vec<String>>` and
  `failure_reason: Option<String>` become structural (e.g.
  `observed: Option<BTreeSet<String>>` keeps data; `failure_reason`
  becomes an enum with the failure modes the renderer turns into prose).
- `Ann::RegexMatch.pattern: String` and `actual: String` stay (these are
  the literal regex source and literal input — already structural).
- `Ann::BindMatch.value: Option<String>` stays (binding-captured value).
- Any other variant whose field name encodes display intent ("…_text",
  "label", pre-quoted strings) gets the same treatment.

The text renderer (`trace_to_layout` / its successor) and JSON renderer
(`trace_to_json`) each own the mapping from structural data to their
output form. JSON output is unchanged because the keys it emits already
match the structural shape.

**Alternative considered:** keep `Ann` shape and add a parallel
"structured trace" surface. Rejected — two parallel traces double the
producer's work and let the old shape rot.

**Alternative considered:** type-parameterise `Ann` over a "render
target" so different renderers see different field shapes. Rejected —
no second text-style renderer exists; YAGNI. The simple cut is to put
formatting where formatting belongs.

### 2. `output/transform.rs` collapses to one entry point

`prepare_doc_for_text(doc: Doc<Option<Ann>>) -> Doc<Option<Ann>>` becomes
the only function `render_annotated_rule` (and the one other call site)
sees. Inside, `distribute_arg_annotations`, `truncate_matched_anywhere`,
`truncate_unevaluated`, `dim_unevaluated` become private helpers, called
in the order the implementation knows is correct.

**Alternative considered:** keep the four passes public-within-module
and document the order in a comment on `render_annotated_rule`.
Rejected — the documentation rots; collapsing the surface is the
cheapest enforcement.

**Alternative considered:** fuse the four recursions into a single walk.
Rejected for this change — that is a perf concern orthogonal to the
seam-narrowing. The collapse makes fusion a local change later if
profiling motivates it.

### 3. `TraceLayoutBuilder` replaces inline state in `trace_to_layout`

A private struct in `src/output/mod.rs` (or a new
`src/output/trace_layout.rs`) holds the six state slots
(`pending_command`, `current_rows`, `last_shown_facts`, `pending_parsers`,
`first`, `has_segments`) as fields. Methods:

- `on_segment_header(command, decision)`
- `on_rule(rule_entry)`
- `on_embedded_command(source, decision)`
- `on_default_ask(reason)`
- `on_parser(parser_entry)` — buffers the parser row
- `on_parse_diagnostics(diagnostics)`
- `finish(indent) -> Layout`

The "parser row binds to next matching command row" rule becomes a
helper (`take_pending_parser(&mut self, command: &str) -> Option<ColRow>`)
called from `on_rule`. `trace_to_layout` becomes a 20-line driver that
iterates the entries and dispatches to the named methods.

**Alternative considered:** model trace entries as a stream and
fold-compose into a `Layout` purely functionally. Rejected — the
parser-buffering rule plus the facts-dedup rule make the state real;
hiding it in a fold-accumulator makes the rules harder to name.

**Alternative considered:** keep the inline loop and extract just the
helper functions. Rejected — the state coupling is the source of
fragility; extracting helpers without a place to hold the state leaves
each helper taking five arguments.

### 4. `tasks.md`-only landing for candidates 2 and 3

Both refactors preserve every requirement currently in the
`output-rendering` and `traces` specs. They do not introduce new
contractual behaviour, so no spec delta is warranted. The constraint
they establish — module-private composition — is already a consequence
of the existing `output-rendering` requirement that no `cmd_*` module
constructs `Layout` values.

### 5. Snapshot contract

Every existing snapshot under `tests/`, `src/snapshots/`, and the
crate-level `snapshots/` (if any) MUST pass without manual approval.
Snapshot diffs during implementation indicate a bug in the refactor,
not an intended output change. The JSON renderer's output bytes MUST
also be unchanged — the test plan in tasks.md includes a JSON snapshot
verification step.

## Risks / Trade-offs

- **Hidden text-renderer dependency on string shape.** Risk: a
  downstream text-renderer detail (e.g. spacing inside the
  "until <tok>…" rendering) was inadvertently encoded into the
  producer-side string and the new structural form drops a space.
  → Mitigation: snapshot tests cover the rendered bytes. Implement
  one variant at a time and re-run the full snapshot suite per change.
- **`Ann` field rename ripples.** `Ann` is consumed by both text and
  JSON renderers and by tests. Renaming fields touches many sites.
  → Mitigation: do the rename as a single mechanical step per variant;
  rely on the compiler to find every site.
- **JSON output drift via field-name changes.** If a new structural
  field gets a different JSON key than the string it replaced, JSON
  consumers break.
  → Mitigation: keep JSON keys identical by explicit `serde` rename if
  the Rust field name changes. The JSON snapshot tests verify.
- **`TraceLayoutBuilder` becomes a god-object.** Risk: the builder
  accumulates every rendering concern until it's worse than the
  original loop.
  → Mitigation: scope is exactly the seven methods above. New rendering
  concerns that don't fit one of these methods are a signal to add a
  named helper, not a flag or branch inside an existing method.
- **Test churn for the trace producer.** Tests on `TracingFold` that
  asserted formatted strings (e.g. `assert_eq!(parser.flags, "until …")`)
  must move to renderer-level tests. Producer tests assert structural
  shape only.
  → Mitigation: identify and migrate these tests as part of the
  candidate-1 implementation. The migration is bounded — these tests
  live in `src/annotation.rs` and the `output/` test modules.

## Migration Plan

Pre-1.0; no user-facing migration. Implementation order:

1. Land candidate 3 (LayoutBuilder) first — purely local to
   `output/mod.rs`, no `Ann`/`TraceEntry` changes, lowest blast radius.
2. Land candidate 2 (transform collapse) — local to
   `output/transform.rs` and its two call sites.
3. Land candidate 1 (structural trace IR) — touches `annotation.rs`,
   both renderers, the new `traces` requirement, and producer-side
   tests. Largest blast radius; lands last on a stable foundation.

Each step runs `cargo fmt`, full test suite, and `cargo tarpaulin` per
CLAUDE.md.

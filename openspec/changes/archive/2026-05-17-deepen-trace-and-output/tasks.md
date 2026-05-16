## 1. Extract TraceLayoutBuilder (candidate 3)

- [x] 1.1 Add private `TraceLayoutBuilder` struct in `src/output/mod.rs` (or new `src/output/trace_layout.rs`) holding the six state slots currently inline in `trace_to_layout`: `pending_command`, `current_rows`, `last_shown_facts`, `pending_parsers`, `first`, `has_segments`.
- [x] 1.2 Implement methods `on_segment_header`, `on_rule`, `on_embedded_command`, `on_default_ask`, `on_parser`, `on_parse_diagnostics`, `finish` — each carrying the per-arm logic from the current loop's `match`.
- [x] 1.3 Extract `take_pending_parser(&mut self, command: &str) -> Option<ColRow>` as a named helper for the "parser row binds to next matching command" rule.
- [x] 1.4 Replace `trace_to_layout`'s body with a thin driver that constructs the builder, dispatches each `TraceEntry` to the matching method, and returns `builder.finish(indent)`.
- [x] 1.5 Run `cargo fmt`, full test suite, and verify every snapshot under `tests/`, `src/snapshots/`, and `crates/*/src/snapshots/` passes without manual approval.

## 2. Collapse output/transform.rs surface (candidate 2)

- [x] 2.1 Introduce private `prepare_doc_for_text(doc: Doc<Option<Ann>>) -> Doc<Option<Ann>>` in `src/output/transform.rs` that internally calls `distribute_arg_annotations`, `truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated` in the order today's call sites use.
- [x] 2.2 Demote `distribute_arg_annotations`, `truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated` from `pub(super)` to private (`fn`).
- [x] 2.3 Update `src/output/render_rule.rs::render_annotated_rule` and any other `output/`-internal call site to call `prepare_doc_for_text` instead of composing the four passes by hand.
- [x] 2.4 Move any tests under `src/output/transform.rs` that exercise individual passes to exercise `prepare_doc_for_text` end-to-end; preserve coverage of each pass's distinctive behaviour (anywhere truncation, unevaluated truncation, dimming propagation, annotation distribution).
- [x] 2.5 Run `cargo fmt`, full test suite, snapshot verification.

## 3. Narrow Ann and TraceEntry to structural data (candidate 1)

- [x] 3.1 Audit `Ann` and `TraceEntry` variants for fields populated via display-format helpers or pre-rendered strings. Produce a per-field list of (current type → structural type → renderer-side formatting fn).
- [x] 3.2 Replace `TraceEntry::Parser.flags: String` with a structural representation (e.g. `FlagsRendering` enum covering `Posix | Permute | Until(Vec<String>)`); update `TracingFold` to populate it without formatting.
- [x] 3.3 Replace `Ann::FactQuery.observed: Option<Vec<String>>` and `failure_reason: Option<String>` with structural fields (e.g. observed values as `Option<BTreeSet<String>>`; failure mode as a `FactFailure` enum with the failure cases the renderer turns into prose).
- [x] 3.4 For any other variant identified in 3.1, apply the same shape: TracingFold records data, renderers format.
- [x] 3.5 Update `src/output/mod.rs` text-rendering paths (now in `TraceLayoutBuilder` from §1) to format from the new structural fields. Add `#[cfg(test)]` helpers if needed so renderer unit tests do not duplicate format logic.
- [x] 3.6 Update `src/output/json.rs::trace_to_json` to read the structural fields; preserve JSON key names and value shapes exactly (use explicit `serde` field renames where Rust field names changed).
- [x] 3.7 Migrate `TracingFold` tests that asserted formatted strings (e.g. `assert_eq!(parser.flags, "until …")`) to assert structural shape; add renderer-level tests for the formatting that moved.

## 4. Verification

- [x] 4.1 Run `cargo fmt` and confirm no diff.
- [x] 4.2 Run the full `cargo test` suite (workspace).
- [x] 4.3 Confirm every snapshot under `tests/`, `src/snapshots/`, and `crates/*/src/snapshots/` passes without `cargo insta accept` (i.e. zero `.snap.new` files).
- [x] 4.4 Run `cargo tarpaulin` per CLAUDE.md; inspect `lcov.info` for regressions in the modified files (`src/annotation.rs`, `src/output/mod.rs`, `src/output/transform.rs`, `src/output/json.rs`, `src/output/render_rule.rs`). Add property or unit tests for any newly-uncovered branches.
- [x] 4.5 Run `openspec validate deepen-trace-and-output --strict`.
- [x] 4.6 Confirm `tests/` JSON-mode assertions still pass byte-for-byte; if any JSON snapshot exists for `--json` mode, verify it.

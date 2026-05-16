## 1. Define the funnel signature and module placement

- [ ] 1.1 Confirm `trace_to_layout(entries: &[TraceEntry], command: &str, indent: usize, term: &Terminal) -> Layout` in `src/output/mod.rs` is the right home (already exists as a private helper called by `render_trace`)
- [ ] 1.2 Add a module-level docstring on `trace_to_layout` that names the ordered rewrite steps it owns (truncate-matched-anywhere → truncate-unevaluated → dim-unevaluated → distribute-arg-annotations) and states it is the sole call site for those passes
- [ ] 1.3 Decide on the shared intermediate per `design.md` (`PreparedTrace` vs serialising from `Layout`); record the choice in a code comment at the funnel's site

## 2. Move each rewrite pass into the funnel as a named ordered step

- [ ] 2.1 In `trace_to_layout` (or a private helper it calls), invoke the rewrite passes in the documented order; the call site is the only one in `src/output/`
- [ ] 2.2 Reduce `prepare_doc_for_text` in `src/output/transform.rs` to a private helper of the funnel (drop `pub(super)` if it has no callers outside the funnel after step 3)
- [ ] 2.3 Confirm no orphan public re-exports of individual passes (`truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated`, `distribute_arg_annotations`) survive

## 3. Port the text renderer to consume the prepared shape

- [ ] 3.1 Update `render_trace` / `write_trace` in `src/output/mod.rs` to receive the `Layout` built by `trace_to_layout` with no additional rewrites
- [ ] 3.2 Update `src/output/render_rule.rs` to read the prepared doc (or its successor in `PreparedTrace`) rather than calling `prepare_doc_for_text` itself
- [ ] 3.3 `rg 'prepare_doc_for_text|truncate_matched_anywhere|truncate_unevaluated|dim_unevaluated|distribute_arg_annotations' src/output/` returns matches only inside the funnel function's body or its private helpers in `transform.rs`

## 4. Port the JSON renderer to consume the prepared shape

- [ ] 4.1 Update `trace_to_json` in `src/output/json.rs` to take the prepared trace artefact (or to walk the `Layout`) instead of walking the raw `Doc<Option<Ann>>` per rule
- [ ] 4.2 Kill the parallel `collect_json_annotations` / `doc_to_json` walks of unprepared data — any structural decisions (dimming, truncation) come from the prepared shape
- [ ] 4.3 `rg 'truncate_matched_anywhere|truncate_unevaluated|dim_unevaluated|distribute_arg_annotations' src/output/json.rs` returns zero hits
- [ ] 4.4 `render_check_results_json` continues to call `trace_to_json` via the new signature (callers updated if the signature changes)

## 5. Re-confirm renderer boundaries

- [ ] 5.1 `rg 'truncate_matched_anywhere|truncate_unevaluated|dim_unevaluated|distribute_arg_annotations|prepare_doc_for_text' src/cmd_*.rs src/main.rs` returns zero hits
- [ ] 5.2 `rg 'pub use.*(truncate|dim_unevaluated|distribute_arg_annotations|prepare_doc_for_text)' src/` returns zero hits

## 6. Review snapshots and tests

- [ ] 6.1 `cargo test` passes; any snapshot diff is investigated and either reverted or recorded with reviewer sign-off in the commit message
- [ ] 6.2 `cargo insta review` on text trace snapshots under `tests/snapshots/` and `crates/may-i-output/src/snapshots/`; expectation is zero accepted diffs
- [ ] 6.3 `cargo insta review` on JSON trace snapshots (`src/output/json.rs` tests, `tests/snapshots/*json*`); expectation is zero accepted diffs

## 7. Validate, lint, format

- [ ] 7.1 `cargo fmt` clean
- [ ] 7.2 `cargo tarpaulin` runs; inspect `lcov.info` for any newly uncovered branch introduced by the funnel restructure and add targeted unit tests (proptests preferred) for it per `CLAUDE.md`
- [ ] 7.3 `openspec validate funnel-output-rewrites` passes
- [ ] 7.4 `openspec status --change funnel-output-rewrites` shows 4/4 complete

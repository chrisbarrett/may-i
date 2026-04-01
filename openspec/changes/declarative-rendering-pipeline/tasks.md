## 1. Modularize output.rs (Phase 1)

- [ ] 1.1 Create `src/output/` directory with `mod.rs` that re-exports the existing public API
- [ ] 1.2 Extract `colorize.rs` -- move `colorize_right`, `colorize_decision_keyword`, `colorize_effect_sexpr` and their tests
- [ ] 1.3 Extract `transform.rs` -- move `truncate_matched_anywhere`, `truncate_unevaluated`, `dim_unevaluated` and their tests
- [ ] 1.4 Extract `annotate.rs` -- move `collect_annotations`, `collect_annotations_inner`, `format_annotation`, positional helpers and their tests
- [ ] 1.5 Extract `render_rule.rs` -- move `render_annotated_rule`, `find_line`, `node_text`, `extract_outcome`, `has_match` and their tests
- [ ] 1.6 Extract `json.rs` -- move `trace_to_json`, `collect_json_annotations`, `ann_to_json`, `doc_to_json` and their tests
- [ ] 1.7 Move shared test helpers to a `#[cfg(test)]` helper module accessible to all submodules
- [ ] 1.8 Verify: `cargo test`, `cargo clippy`, oracle snapshots pass with identical output

## 2. Define PrettyOutput trait (Phase 2)

- [ ] 2.1 Define `PrettyOutput<A>` trait in `crates/pp/src/lib.rs` with `begin_line`, `emit_space`, `emit_delim`, `emit_atom` methods
- [ ] 2.2 Define `OutputEvent` enum for flat-rendering event buffer
- [ ] 2.3 Implement `StringBuilder` as `PrettyOutput<A>` reproducing current `render_atom`/colorization behavior
- [ ] 2.4 Reimplement `pretty()` as a wrapper over `pretty_into()` + `StringBuilder`, verify identical output

## 3. Refactor render functions to use trait

- [ ] 3.1 Change `render()` signature from returning `String` to accepting `&mut impl PrettyOutput<A>`
- [ ] 3.2 Refactor `render_flat` to buffer `OutputEvent`s, measure width, replay if fits
- [ ] 3.3 Refactor `render_broken`, `render_all_drop`, `render_cond`, `render_body_indent` to emit via trait
- [ ] 3.4 Add `pretty_into<A>(doc, indent, fmt, &mut impl PrettyOutput<A>)` public entry point
- [ ] 3.5 Verify: all pp crate tests pass, `pretty()` wrapper produces identical output

## 4. Implement AnnotatedLineBuilder

- [ ] 4.1 Define `AnnotatedLine<A>` struct with `text`, `visible_width`, `annotations` fields
- [ ] 4.2 Implement `AnnotatedLineBuilder<A: Clone>` as `PrettyOutput<A>` with per-line annotation collection
- [ ] 4.3 Add property tests: `AnnotatedLineBuilder` text output matches `StringBuilder` for arbitrary `Doc<()>` inputs
- [ ] 4.4 Add unit tests: annotations correctly associated with their rendered lines in broken and flat layouts

## 5. ArgMatch annotation distribution

- [ ] 5.1 Implement `distribute_arg_annotations` transform: propagate parent `Ann::ArgMatch` to individual token atom children
- [ ] 5.2 Handle nested patterns: `(not (anywhere ...))` for forbidden patterns
- [ ] 5.3 Add tests verifying per-token annotation distribution for anywhere, forbidden, and positional patterns

## 6. Replace find_line pipeline in render_rule

- [ ] 6.1 Update `render_annotated_rule` to use `pretty_into` + `AnnotatedLineBuilder` instead of `pretty` + `collect_annotations` + `find_line`
- [ ] 6.2 Implement `format_line_annotation` that maps `Vec<Ann>` from each `AnnotatedLine` to right-column text
- [ ] 6.3 Remove `find_line`, `node_text`, `collect_annotations`, `collect_annotations_inner` from `annotate.rs`
- [ ] 6.4 Verify: oracle snapshot tests produce byte-identical output
- [ ] 6.5 Verify: `cargo test`, `cargo clippy`, `cargo tarpaulin` all pass

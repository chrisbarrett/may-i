## 1. Suppress annotations for dimmed nodes

- [ ] 1.1 In `render()` in `crates/pp/src/lib.rs`, gate `emit_node_ann` calls on `!dimmed` for List and Vector branches
- [ ] 1.2 In `AnnotatedLineBuilder::emit_atom`, skip annotation collection when `dimmed` is true
- [ ] 1.3 Add test: `AnnotatedLineBuilder` produces no annotations for a fully-dimmed doc tree
- [ ] 1.4 Add test: mixed dimmed/non-dimmed tree only collects annotations from non-dimmed nodes

## 2. Implement format_line_annotation

- [ ] 2.1 Add `format_line_annotation(anns: &[Ann]) -> String` in `render_rule.rs` that maps a line's annotations to right-column text using priority ordering
- [ ] 2.2 Handle all Ann variants: EffectDecision, MayI, BindMatch, RegexMatch, FactQuery, CommandMatch, ArgMatch (per-token), PositionalMatch, Combinator, RuleMatch
- [ ] 2.3 Add tests for each annotation type producing correct right-column text
- [ ] 2.4 Add test: multiple annotations on one line → highest-priority wins

## 3. Wire AnnotatedLineBuilder into render_annotated_rule

- [ ] 3.1 Replace `pretty()` + `collect_annotations()` + `find_line()` with `pretty_into()` + `AnnotatedLineBuilder` + `distribute_arg_annotations` + `format_line_annotation`
- [ ] 3.2 Keep `extract_outcome` fallback: if no line already has an EffectDecision annotation, place it on the `(effect` line
- [ ] 3.3 Verify: oracle snapshot tests produce byte-identical output
- [ ] 3.4 Remove `#[allow(dead_code)]` from `distribute_arg_annotations` in `transform.rs`

## 4. Remove dead code

- [ ] 4.1 Remove `collect_annotations`, `collect_annotations_inner`, `node_text` from `annotate.rs`
- [ ] 4.2 Remove `find_line` from `render_rule.rs`
- [ ] 4.3 Remove tests for removed functions
- [ ] 4.4 Verify: `cargo test`, `cargo clippy`, `cargo tarpaulin` all pass

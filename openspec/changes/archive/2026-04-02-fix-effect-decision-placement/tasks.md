## 1. Suppress annotations for dimmed nodes

- [x] 1.1 In `render()` in `crates/pp/src/lib.rs`, gate `emit_node_ann` calls on `!dimmed` for List and Vector branches
- [x] 1.2 In `AnnotatedLineBuilder::emit_atom`, skip annotation collection when `dimmed` is true
- [x] 1.3 Add test: `AnnotatedLineBuilder` produces no annotations for a fully-dimmed doc tree
- [x] 1.4 Add test: mixed dimmed/non-dimmed tree only collects annotations from non-dimmed nodes

## 2. Implement format_line_annotation

- [x] 2.1 Add `format_line_annotation(anns: &[Ann]) -> String` in `render_rule.rs` that maps a line's annotations to right-column text using priority ordering
- [x] 2.2 Handle all Ann variants: EffectDecision, MayI, BindMatch, RegexMatch, FactQuery, CommandMatch, ArgMatch (per-token), PositionalMatch, Combinator, RuleMatch
- [x] 2.3 Add tests for each annotation type producing correct right-column text
- [x] 2.4 Add test: multiple annotations on one line → highest-priority wins

## 3. Wire AnnotatedLineBuilder into render_annotated_rule

- [x] 3.1 Replace `pretty()` + `collect_annotations()` + `find_line()` with `pretty_into()` + `AnnotatedLineBuilder` + `distribute_arg_annotations` + `format_line_annotation`
- [x] 3.2 Move EffectDecision from trailing-cond continuation to matching cond branch body via `move_ann_to_cond_branch` + `cond_branch_index` in fold (structural, no string matching)
- [x] 3.3 Verify: oracle snapshot tests produce byte-identical output
- [x] 3.4 Remove `#[allow(dead_code)]` from `distribute_arg_annotations` in `transform.rs`

## 4. Remove dead code

- [x] 4.1 Remove `collect_annotations`, `collect_annotations_inner`, `node_text`, `format_annotation`, `extract_positional_args`, `collect_positional_annotations`, `collect_pattern_comparisons` from `annotate.rs`
- [x] 4.2 Remove `find_line` from `render_rule.rs` (already removed in 3.1)
- [x] 4.3 Remove tests for removed functions
- [x] 4.4 Verify: `cargo test`, `cargo clippy`, `cargo tarpaulin` all pass

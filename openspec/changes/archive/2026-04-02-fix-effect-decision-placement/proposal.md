## Why

Phase 6 of the `declarative-rendering-pipeline` change cannot complete because
`AnnotatedLineBuilder` captures `EffectDecision` annotations from dimmed
(unevaluated) branches, producing duplicate and misplaced right-column
annotations that break oracle snapshot tests. The current `find_line`
string-matching pipeline works around this implicitly via sequential search and
`already_has_effect_decision` guards, but the structural approach needs explicit
handling.

## What Changes

- Suppress `emit_node_ann` calls for dimmed nodes in the pp crate's `render()`
  function, so unevaluated branches don't contribute annotations to
  `AnnotatedLineBuilder`.
- Implement `format_line_annotation` in `render_rule.rs` that maps
  `Vec<Ann>` from each `AnnotatedLine` to right-column text, with deduplication
  logic for competing `EffectDecision` annotations.
- Wire `AnnotatedLineBuilder` into `render_annotated_rule`, replacing
  `collect_annotations` + `find_line`.
- Remove dead code: `find_line`, `node_text`, `collect_annotations`,
  `collect_annotations_inner` from `annotate.rs`.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `trace-rendering`: Annotation placement becomes structural (per-line from
  `AnnotatedLineBuilder`) instead of string-match based (`find_line`). No
  user-visible requirement changes — terminal and JSON output remain identical.

## Impact

- `crates/pp/src/lib.rs`: `render()` gains a dimmed check before
  `emit_node_ann`
- `src/output/render_rule.rs`: replaces `pretty` + `collect_annotations` +
  `find_line` with `pretty_into` + `AnnotatedLineBuilder` +
  `format_line_annotation`
- `src/output/annotate.rs`: `collect_annotations`, `collect_annotations_inner`,
  `node_text`, `find_line` removed
- `src/output/transform.rs`: `distribute_arg_annotations` `#[allow(dead_code)]`
  removed (now used)
- Oracle snapshot tests must remain byte-identical

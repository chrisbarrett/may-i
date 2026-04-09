## Why

Property-based testing catches edge cases that hand-written tests miss. Several areas with complex logic lack proptest coverage: config parsing roundtrips, CST pretty-printing, positional pattern backtracking, cycle detection in define graphs, and expression parsing.

## What Changes

- Add config parse roundtrip proptest: generate Config AST → serialize to sexpr → parse back → compare (semantic layer, complementing existing sexpr-level roundtrip)
- Add CST `pretty_serialize` roundtrip proptest: parse → pretty_serialize(width) → parse → compare structure
- Add positional matching backtracking proptest: verify consumed + unconsumed = original args, greedy semantics
- Add define-graph cycle detection proptest: generate random define graphs, verify acyclic pass / cyclic rejected
- Add expression parser roundtrip proptest: generate Expr → serialize → parse → compare
- Add `render_annotated_rule` never-panics proptest using existing `any_config` generator
- Add `word_wrap` proptest in layout crate: all words preserved, no line exceeds width

## Capabilities

### New Capabilities

- `proptest-coverage`: Property tests for config parsing, CST formatting, pattern matching, and rendering

### Modified Capabilities

- `cst-roundtrip`: Add pretty_serialize roundtrip property
- `pattern-expressions`: Add expression parser roundtrip property

## Impact

- `crates/config/` — parse roundtrip proptest
- `crates/sexpr/src/cst.rs` — pretty roundtrip proptest
- `crates/engine/src/eval/positional.rs` — backtracking proptest
- `crates/config/src/resolve.rs` — cycle detection proptest
- `crates/config/src/pattern.rs` — expression roundtrip proptest
- `src/output/render_rule.rs` — never-panics proptest
- `crates/layout/src/lib.rs` — word_wrap proptest

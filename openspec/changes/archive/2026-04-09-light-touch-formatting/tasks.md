## 1. Source trivia detection

- [x] 1.1 Add `fn has_source_trivia(&self) -> bool` method on `CstNode<TriviaAnn>` that returns true when the span is non-zero (`span.start != 0 || span.end != 0`)
- [x] 1.2 Add unit tests: parsed node returns true, `Default::default()` node returns false, node at byte offset 0 with non-zero end returns true

## 2. Trivia-aware child dispatch in pretty_write

- [x] 2.1 In `pretty_write`'s list rendering loop, change `child.pretty_write_no_whitespace(ctx)` to dispatch: if `child.has_source_trivia()` use `child.pretty_write(ctx)`, otherwise use `child.pretty_write_no_whitespace(ctx)`
- [x] 2.2 Apply the same dispatch in `pretty_write`'s vector rendering loop
- [x] 2.3 Apply the same dispatch for keyword-value pairs (the `children[i + 1]` write)

## 3. Tests for preserved layout

- [x] 3.1 Add test: parse a packed `(or "a" "b" "c" "d")`, apply a rewrite that wraps it in `(rule "x" <or-node>)` cloning the or node, verify `pretty_serialize` preserves the packed layout
- [x] 3.2 Add test: parse a multi-line packed `(or "a" "b"\n    "c" "d")`, apply a wrapping rewrite, verify line breaks are preserved
- [x] 3.3 Add test: parse a cascaded `(or (foo)\n    (bar))`, apply a wrapping rewrite, verify cascaded layout is preserved
- [x] 3.4 Add test: verify freshly constructed nodes (default trivia) still use reflow rendering

## 4. Update existing tests

- [x] 4.1 Run `cargo test` and fix any assertions that changed due to preserved-trivia rendering
- [x] 4.2 Update migration diff snapshot in `tests/migration_diff.rs` if needed

## 5. Validation

- [x] 5.1 Run `cargo run -- migrate` against `~/.config/may-i/config.lisp` and verify the diff is smaller than before (packed `or` lists no longer explode)
- [x] 5.2 Verify the migration output parses correctly (`cargo run -- check` succeeds on migrated output)

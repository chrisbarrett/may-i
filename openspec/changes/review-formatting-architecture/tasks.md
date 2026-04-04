## 1. TriviaSource trait and implementations

- [ ] 1.1 Define `TriviaSource` trait in `pp` crate with `forced_break()`, `leading_trivia()`, `trailing_trivia()` methods
- [ ] 1.2 Implement `TriviaSource` for `()` (all no-ops: no forced break, empty trivia)
- [ ] 1.3 Implement `TriviaSource` for `Option<TriviaAnn>` (delegate to trivia when `Some`, no-ops when `None`)
- [ ] 1.4 Unit tests for both implementations

## 2. Trivia emission in PrettyOutput

- [ ] 2.1 Add `emit_leading_trivia(&mut self, trivia: &[Trivia], indent: usize)` to `PrettyOutput` trait with default implementation (comment-on-own-line at indent, blank line preservation)
- [ ] 2.2 Add `emit_trailing_trivia(&mut self, trivia: &[Trivia])` to `PrettyOutput` trait with default implementation
- [ ] 2.3 Implement trivia emission in `StringBuilder` (emit comments and preserved whitespace)
- [ ] 2.4 Implement trivia emission in `EventBuffer` (record events and track width)
- [ ] 2.5 Implement trivia emission in `AnnotatedLineBuilder`

## 3. Trivia-aware render function

- [ ] 3.1 Add `A: TriviaSource` bound to the `render` function
- [ ] 3.2 In list child rendering: check `forced_break()` before speculative layout; if forced, emit trivia and break
- [ ] 3.3 Emit leading trivia before each child that carries it
- [ ] 3.4 Emit trailing trivia after each node that carries it
- [ ] 3.5 Cascade semantics: forced break from trivia sets cascade for subsequent children
- [ ] 3.6 Verify `Doc<()>` rendering is unchanged (run existing `pp` tests)

## 4. Unified special-form table

- [ ] 4.1 Create single `SPECIAL_FORMS` table in `pp` crate (or `core`): `rule`, `define`, `check`, `with-facts`, `when`, `unless`, `if`, `cond`, `case`
- [ ] 4.2 Export `is_special_form()` from the chosen crate
- [ ] 4.3 Update `render` to use the unified table for indent decisions
- [ ] 4.4 Verify indent behaviour matches current output for both `pp` and `cst.rs` consumers

## 5. CstNode::to_doc_with_trivia()

- [ ] 5.1 Implement `to_doc_with_trivia(&self) -> Doc<Option<TriviaAnn>>` on `CstNode<TriviaAnn>`
- [ ] 5.2 Source-parsed nodes (non-zero span) get `Some(trivia_ann)`, constructed nodes get `None`
- [ ] 5.3 Unit tests: roundtrip parsed CST through `to_doc_with_trivia` and verify trivia annotations are present/absent correctly

## 6. Reimplement pretty_serialize

- [ ] 6.1 Replace `pretty_serialize` body with `to_doc_with_trivia()` + `pp::pretty()`
- [ ] 6.2 Remove `PrettyCtx`, `pretty_write`, `pretty_write_no_whitespace`, `compute_child_indent`, `estimate_width`, `SPECIAL_FORMS` table, and `is_special_form` from `cst.rs`
- [ ] 6.3 Verify `serialize()` (faithful roundtrip) is unchanged

## 7. Update tests and snapshots

- [ ] 7.1 Run `cargo test` across all crates, fix assertions that changed due to the new renderer
- [ ] 7.2 Update migration diff snapshots in `tests/migration_diff.rs`
- [ ] 7.3 Verify migration output parses correctly (`validate_migration` passes)

## 8. Validation

- [ ] 8.1 Run migration against sample configs, verify diffs are clean
- [ ] 8.2 Compare trace output before and after — should be identical for `Doc<()>` rendering
- [ ] 8.3 Verify constructed nodes in migration output get better layout than before (manual inspection)

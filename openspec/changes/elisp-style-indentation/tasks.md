## 1. Special-form lookup table

- [ ] 1.1 Add a `fn is_special_form(name: &str) -> bool` function (or const `&[&str]` table) in `crates/sexpr/src/cst.rs` covering: `define`, `check`, `with-facts`, `when`, `unless`, `rule`, `cond`
- [ ] 1.2 Add unit tests confirming classification of known special forms and non-special forms

## 2. Form-aware indentation

- [ ] 2.1 Modify the list-formatting path in `pretty_write` and `pretty_write_no_whitespace` to compute `child_indent` based on form classification: special forms use `head_col + 2`, function-call forms use `head_col + 1 + head_atom_width + 1`, fallback to `head_col + 1` for non-atom heads
- [ ] 2.2 Add tests for special-form indent (+2 body) with `define`, `check`, `rule`
- [ ] 2.3 Add tests for function-call indent (align under first arg) with `or`, `and`, `positional`
- [ ] 2.4 Add test for non-atom head fallback

## 3. Comment positioning

- [ ] 3.1 Modify `pretty_write_no_whitespace` to classify comments as whole-line vs line-trailing by inspecting the preceding `Trivia::Whitespace` for `\n`
- [ ] 3.2 For whole-line comments: emit newline + current indent before the comment text; preserve blank lines (extra newlines in preceding whitespace)
- [ ] 3.3 For line-trailing comments: emit the preceding `Trivia::Whitespace` as-is before the comment
- [ ] 3.4 Add tests: whole-line comment indented at current level, blank line before comment preserved, line-trailing comment gap preserved

## 4. Update existing tests

- [ ] 4.1 Update `pretty_serialize` tests in `crates/sexpr/src/cst.rs` to match new indentation output
- [ ] 4.2 Update migration diff snapshot in `tests/migration_diff.rs`
- [ ] 4.3 Run `cargo test` and fix any remaining assertion failures

## 5. Validation

- [ ] 5.1 Run `cargo run -- migrate` against `~/.config/may-i/config.lisp` and verify the diff is minimal (only structural syntax changes, not reformatting noise)

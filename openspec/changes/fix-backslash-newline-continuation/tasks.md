## 1. Audit existing behaviour

- [x] 1.1 Confirm heredoc body reader does not delegate to
  `read_word_parts` / `read_double_quoted_parts`; if it does, plan a
  fix to preserve `\<NL>` verbatim in quoted heredoc bodies
- [x] 1.2 Grep `crates/shell-parser/src/tests/` and any engine tests
  for assertions that depend on the current buggy behaviour (a
  `WordPart::Literal("\n")` at the start of a word). Treat hits as
  bug encodings to delete or invert

## 2. Failing tests first

- [x] 2.1 Add a failing unit test in
  `crates/shell-parser/src/tests/word.rs` covering the post-operator
  continuation scenario from the spec (`mkdir -p foo && \<NL>   ls bar`)
- [x] 2.2 Add a failing unit test for mid-word continuation
  (`ec\<NL>ho hi`)
- [x] 2.3 Add a failing unit test for double-quoted continuation
  (`echo "foo\<NL>bar"`)
- [x] 2.4 Add a failing unit test for single-quoted literal
  preservation (`echo 'foo\<NL>bar'`)
- [x] 2.5 Add a failing unit test for quoted-heredoc literal
  preservation (`cat <<'EOF'\nfoo\<NL>bar\nEOF\n`)
- [x] 2.6 Add a failing engine integration test asserting that
  `evaluate_command` on the multi-line `&&` chain from the
  2026-05-18 incident reports the real command name, not `\n`

## 3. Lexer change

- [x] 3.1 In `crates/shell-parser/src/lexer/word_parts.rs`, change
  the `Some('\\')` arm of `read_word_parts` to detect a following
  `'\n'` and consume both without pushing a `WordPart`
- [x] 3.2 Apply the same change inside `read_double_quoted_parts`
- [x] 3.3 Verify by reading the heredoc body reader that no
  additional change is needed in the heredoc context; otherwise add
  the corresponding guard

## 4. Property tests

- [x] 4.1 Add a proptest in `crates/shell-parser/src/tests/` that
  generates arbitrary commands with random `\<NL>` insertions in
  unquoted positions and asserts the parsed command name matches the
  same input with all `\<NL>` removed before parsing
- [x] 4.2 Add a proptest that asserts the `parser-engine-invariants`
  span-bounds property still holds for inputs containing `\<NL>`

## 5. Verification

- [x] 5.1 `cargo fmt`
- [x] 5.2 `cargo test -p may-i-shell-parser`
- [x] 5.3 `cargo test -p may-i-engine`
- [x] 5.4 `cargo test` (workspace)
- [x] 5.5 `cargo tarpaulin` and inspect `lcov.info` for uncovered
  branches in the modified arms
- [x] 5.6 Reproduce the incident command end-to-end via
  `printf '…' | may-i claude-code-hook` with a config that allows
  `mv`, `mkdir`, `ls`, `tail`; confirm the response is no longer
  `No rule for command \n`

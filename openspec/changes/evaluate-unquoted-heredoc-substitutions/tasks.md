## 1. Record heredoc delimiter quoting (shell-parser)

- [x] 1.1 Write failing tests: the AST records whether a heredoc's opening delimiter was quoted (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) or unquoted (`<<EOF`), and the body's source span.
- [x] 1.2 Extend the heredoc redirection target with a quoted flag and body span; the lexer already distinguishes the quoting forms when reading the delimiter — record instead of discard.

## 2. Extract embedded commands from unquoted heredoc bodies (shell-parser)

- [x] 2.1 Write failing tests: an unquoted heredoc body containing `$(rm --force)`, `` `rm --force` ``, or `$((x))` yields embedded extractions with correct source + span (inner-span semantics); a quoted heredoc body yields none; `<(…)` in a body yields none; an unterminated `$(…` yields none (Error diagnostic instead).
- [x] 2.2 Implement body extraction for unquoted heredocs, reusing the existing embedded-substitution scanner.
- [x] 2.3 Proptest: no embedded command reachable via an unquoted heredoc body escapes extraction; quoted bodies never yield extractions.

## 3. Emit evaluation units (engine)

- [x] 3.1 Write failing eval scenarios: `cat <<EOF` / `$(rm --force)` / `EOF` denies when `rm --force` denies; the quoted forms stay `:allow`; unterminated substitution floors to at least `:ask`.
- [x] 3.2 Emit `EvalUnit::EmbeddedCommand` for unquoted-heredoc-body substitutions in `decompose.rs`, reusing the `$(…)` path.

## 4. Verify

- [x] 4.1 `cargo fmt`; `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 4.2 `cargo test --workspace` green; check in any new `proptest-regressions/`.
- [x] 4.3 Re-run the confirmed bypass against the built binary: unquoted heredoc with `$(rm --force)` now `:deny`.

## 1. Command-position keyword recognition

- [x] 1.1 Write failing parser tests: `find . -name done`, `echo do done fi`, `grep -r fi src`, `ls then` each parse to a Simple command retaining every word, with empty diagnostics.
- [x] 1.2 Add an `at_command_position` flag to the lexer; classify keywords in `read_word_or_keyword` only when set (D1). Set/clear it on separators, operators, list-introducing keywords, and ordinary words; keep it set across leading assignments.
- [x] 1.3 Write failing tests for compound commands that must still parse: `while true; do echo hi; done`, `if true; then echo a; fi`, `{ echo a; }` — assert unchanged AST shape.
- [x] 1.4 Run `parser_snapshots.rs`; reconcile/update snapshots only where the change is intended (well-formed compound commands must be identical).

## 2. `in` resolved in the parser

- [x] 2.1 Write failing tests: `kubectl get pods in default` retains `in` and `default`; `for x in a b; do echo $x; done` still parses as a for-loop.
- [x] 2.2 Remove `in` from lexer keyword classification; consume a literal `in` `Word` in `parse_for` and `parse_case` (D2).

## 3. No silent token loss

- [x] 3.1 Write a failing test: a stray `done` with no opening `do` emits an Error-severity diagnostic and floors the decision to `:ask` (no tokens dropped).
- [x] 3.2 Replace token-dropping `break` paths in `parse_simple_command` / list parsing with an Error-severity `ParseDiagnostic` for an unplaceable reserved word (D3).
- [x] 3.3 Add a proptest: for any input, every command word bash would see appears in the evaluated units OR an Error diagnostic is present (no silent vanishing).

## 4. Decision-level regression & docs

- [x] 4.1 Engine test: `rm -rf done` evaluates with `done` as an argument (rule sees the full argv), not a truncated `rm -rf`.
- [x] 4.2 Run the original reproductions in hook mode; confirm full commands are evaluated.
- [x] 4.3 `cargo fmt`; run `cargo tarpaulin` and check `lcov.info` for uncovered branches in the touched lexer/parser code.
- [x] 4.4 Check in any new `proptest-regressions/` files.

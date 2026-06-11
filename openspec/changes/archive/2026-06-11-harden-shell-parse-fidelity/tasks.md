## 1. Pipeline negation (`!`)

- [x] 1.1 Write a failing shell-parser test: `! kill -0 %1` parses to the same AST as `kill -0 %1` (leading `!` consumed, not a command word).
- [x] 1.2 Write failing engine scenarios: `! kill …` with `kill` denied → `:deny` naming `kill`; `! kubectl …` no rule → `:ask` reason `No rule for command `kubectl``; `find . ! -name foo` with `find` allowed → `:allow` and `!` left in argv.
- [x] 1.3 In `parse_pipeline` (`crates/shell-parser/src/parse.rs`), consume a leading word that is exactly `!` as a transparent negation prefix; parse and return the inner pipeline unchanged (D1, D2). Guard so only the bare single-char `!` matches.
- [x] 1.4 Add a proptest: for any pipeline `P`, `format!("! {P}")` yields the same evaluation decision and command-name resolution as `P`.
- [x] 1.5 Confirm `!`-as-argument is untouched (`find`, `[ ! -f x ]`) — covered by 1.2; add a parser-level case if a gap remains.

## 2. Unterminated-substitution recursion suppression

- [x] 2.1 Write a failing engine test: `grep -n "x$(y" file` with `grep` allowed → `:ask`, reason starts `parse error: unterminated command substitution`, reason does NOT contain `No rule for command`.
- [x] 2.2 Write a guard test (must stay green): `echo $(rm -rf /)` with `echo` allowed, `rm` denied → `:deny` (well-formed substitution still recurses).
- [x] 2.3 In `decompose` (`crates/engine/src/eval/decompose.rs`), skip emitting an `EmbeddedCommand` unit for a substitution whose body span is covered by an Error-severity diagnostic of kind `UnterminatedCommandSubstitution` / `UnterminatedBacktick` (the diagnostic span runs from the sigil and covers the body) (D3).
- [x] 2.4 Verify the existing floor (`aggregate_decision < Ask`) now applies the `parse error: …` reason for 2.1, and that the "Denied command with parse error" scenario still keeps the deny reason (D4).
- [x] 2.5 Confirm unterminated `${…}` / `$((…))` need no extra handling; add a guard test if 2.3 changes their behaviour (Open Question).

## 3. Regression & docs

- [x] 3.1 Run the reproduction commands end-to-end in hook mode (`! kill -0 %1`; bare-`$(` grep) and confirm the new decisions/reasons.
- [x] 3.2 `cargo fmt`; run `cargo tarpaulin` and check `lcov.info` for uncovered branches in the touched code.
- [x] 3.3 Check in any new `proptest-regressions/` files produced.

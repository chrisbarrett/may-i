## 1. Detect expansion-bearing words (shell-parser)

- [x] 1.1 Write failing tests: a `Word` predicate `is_expansion_bearing()` is true for any word containing a dynamic `WordPart` (parameter/command/arithmetic/process substitution), and for literal parts carrying an *unquoted* glob char (`*` `?` `[`), brace group (`{a,b}`), or leading `~`; false for fully-quoted equivalents (`'/tmp/*'`, `"$()"`-free literals) and plain literals.
- [x] 1.2 Implement the predicate over the existing `WordPart` enum, respecting the lexer's per-part quoting context. No AST shape change.
- [x] 1.3 Proptest: `is_expansion_bearing()` never panics on arbitrary parsed words; a word built solely from quoted/literal parts with no metachars is never flagged.

## 2. Carry expansion provenance on binding values (engine)

- [x] 2.1 Write failing test: a parser capturing `$X` into `#var` records the captured token as expansion-bearing; capturing a literal does not.
- [x] 2.2 Add an expansion-bearing flag to the binding value representation (per token), populated at capture time from the originating `Word`. Update `Arbitrary`/generators.

## 3. Suppress allow-ward matches on expansion-bearing words (engine)

- [x] 3.1 Write failing engine scenarios mirroring the spec: `/tmp/$HOME`, `/tmp/*`, `/tmp/{a,../etc}` under a `^/tmp/` allow guard floor to `:ask` with a reason naming the unresolved word; `rm $HOME` against `(positional #p *)` stays `:allow`; `rm /tmp/x` stays `:allow`; `kubectl -n dev-$ENV` floors; `(anywhere (regex "secret"))` deny still fires on `secret$X`.
- [x] 3.2 At the single-token match seam (the `Expr<T>` evaluation entry and the `every?`/`some?` per-element call), when the expression is non-wildcard AND the word is expansion-bearing AND the call is allow-ward, return the suppression sentinel.
- [x] 3.3 In the segment aggregator, convert the sentinel to an at-least-`:ask` floor carrying the unresolved-word reason, reusing the existing raise-to-ask combinator (NOT a synthesized `ParseDiagnostic`).
- [x] 3.4 Confirm `(forbidden …)`, `(not (flag …))`, and `unless`-test matches still fire on expansion-bearing words (tightening is allowed).

## 4. Asymmetric-soundness invariant (proptest)

- [x] 4.1 Property: for arbitrary config + command, replacing any matched literal token with an expansion-bearing variant never moves the aggregate decision toward `:allow` (allow→{allow only if all matched words stay literal/wildcard}; deny stays deny).
- [x] 4.2 Property: floor only ever raises strictness — `:deny` segments are unchanged by the suppression.

## 5. Trace + reason

- [x] 5.1 Trace renders a suppressed match with its evidence and an "unresolved expansion" annotation, not a silent no-match.
- [x] 5.2 The ask reason names the offending word and contains no literal newline.

## 6. Verify

- [x] 6.1 `cargo fmt`; `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 6.2 `cargo test --workspace` green; check in any new `proptest-regressions/`.
- [x] 6.3 Re-run the confirmed bypasses against the built binary; all three now `:ask`.
- [ ] 6.4 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the new seam.

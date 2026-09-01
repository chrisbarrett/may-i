# Tasks: Quote-aware substitution scanning

## 1. Failing tests (red)

- [ ] 1.1 Add unit tests to `crates/shell-parser/src/tests/expansion.rs` pinning every delta-spec scenario: quoted `(`/`)` in `$(…)`, quoted `)` in `<(…)`, quoted `))` inside `$((…))`, `$[a[1]]`, `${FOO:-"a}b"}`, `${x:-a\}b}`, `${arr["a]b"]}`, `` `echo a\`b` ``, and the heredoc-body `$(echo "a)b")` case; each asserts the captured body text, no `Unterminated*` diagnostic, and that trailing commands are not swallowed. Confirm they fail.
- [ ] 1.2 Add the regression pin for the original incident: the `for … do n=$(grep -c 'may_i(' "$f"); echo "$n $f"; done | sort -rn` command parses with a loop body containing `echo` and a trailing `sort` pipeline stage (no `empty command` collapse). Confirm it fails.
- [ ] 1.3 Add a proptest in `crates/shell-parser/src/tests/properties.rs`: for generated substitution bodies, wrapping any `)` in the body in single or double quotes must not change the captured `$(…)` body text, and the quoted form must produce no `UnterminatedCommandSubstitution` diagnostic. Confirm it fails on quoted-delimiter cases.

## 2. Shared quote-aware scanner (green core)

- [ ] 2.1 Create `crates/shell-parser/src/lexer/scan.rs` with the quote state machine and `find_paren_close`, `find_double_paren_close`, `find_bracket_close`, `skip_backtick_body` (per design D1–D2), with unit tests for the state machine (single-quote literal backslash, double-quote escapes, nested depth, backtick-body skipping).

## 3. Rewire construct scans (green)

- [ ] 3.1 Rewire `read_balanced_parens_checked` and `read_until_double_paren_checked` (`string_readers.rs`) to delegate to `scan.rs` and advance `pos`/`byte_pos` past the closing delimiter, returning the raw source slice (design D3). Unit tests 1.1 for `$(…)` and `$((…))` pass.
- [ ] 3.2 Rewire the `$[…]` scan in `read_dollar` (`word_parts.rs:381-392`) onto `find_bracket_close`. `$[a[1]]` test passes.
- [ ] 3.3 Make `read_operand` (`param_expansion.rs:411`) quote-aware: `stops` honoured only unquoted, `\` consumed into the text, `$(`/backtick lifting unchanged (design D4). `${FOO:-"a}b"}` and `${x:-a\}b}` tests pass.
- [ ] 3.4 Make `read_subscript` (`param_expansion.rs:456-490`) quote-aware for the closing `]` (design D3/D4). `${arr["a]b"]}` test passes.
- [ ] 3.5 Make `read_backtick` and the in-double-quotes backtick reader skip a backslash-escaped closing backtick (via `skip_backtick_body`), matching the heredoc variant. `` `echo a\`b` `` test passes.
- [ ] 3.6 Replace `find_balanced_paren_close` / `find_double_paren_close` in `lexer/mod.rs` with calls into `scan.rs` (design D5); heredoc-body scan itself stays quote-blind. Heredoc test passes; incident regression test 1.2 passes.

## 4. Cleanup

- [ ] 4.1 Remove now-dead byte scanners from `lexer/mod.rs`; `debug_read_balanced_parens` still compiles (its engine counterpart was already deleted).
- [ ] 4.2 Update doc comments that describe the old first-delimiter/quote-blind behaviour (`lexer/mod.rs:60-61`, `param_expansion.rs` `read_operand` doc, `string_readers.rs`).
- [ ] 4.3 Add a CHANGELOG entry under Unreleased: quoted delimiters inside substitutions no longer truncate the parse; decisions for such commands move from `ask`/`empty command` to the decision their real structure warrants.

## 5. Verification

- [ ] 5.1 `cargo test -p shell-parser -p engine` green; `cargo test` full workspace green.
- [ ] 5.2 `cargo clippy --all-targets` and `cargo fmt --check` clean.
- [ ] 5.3 Confirm the incident command end-to-end: `may-i eval --json 'for f in tests/*.rs; do n=$(grep -c '\''may_i('\'' "$f"); echo "$n $f"; done | sort -rn'` no longer returns reason `empty command` (decision comes from the real structure).
- [ ] 5.4 REFERENCE.md: verify no user-facing surface change (parsing-correctness fix only); record "verified, no surface change" or update if any wording covers substitution scanning.
- [ ] 5.5 `openspec validate --change quote-aware-substitution-scanning --strict` passes; proptest regressions dir reviewed for new seeds and checked in if present.

## 1. Failing tests

- [x] 1.1 Add an evaluator integration test asserting that `nix shell pkg --command mkfs /dev/sda` evaluates to deny (or ask, depending on fixture rules) under a config containing `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))` and a `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`.
- [x] 1.2 Add an evaluator integration test asserting that `nix shell pkg` (no boundary token) does NOT match the tail-recursing rule and falls through to subsequent rules.
- [x] 1.3 Add an evaluator integration test for `nix shell pkg -c mkfs /dev/sda` confirming the alias `-c` triggers the same recursion as `--command`.
- [x] 1.4 Add a parser-form unit test asserting that `(tail (after [STR…]))` parses to `Tail::AfterToken(Vec<String>)` with the expected entries.
- [x] 1.5 Add a parser-form unit test asserting that `(tail (after []))` is rejected with a clear error.
- [x] 1.6 Add a unit test asserting that `evaluate_tail_authorise_fold` returns no-match when `parser.tail.is_some()` and the boundary token is absent in argv.
- [x] 1.7 Add a unit test asserting that `evaluate_tail_authorise_fold` falls back to full argv when `parser.tail.is_none()` (existing behaviour preserved).

## 2. Core type extension

- [x] 2.1 Change `Tail::AfterToken(String)` to `Tail::AfterToken(Vec<String>)` in `crates/core/src/ast.rs`.
- [x] 2.2 Update the `Display` impl for `Tail` to render `(after "TOK")` when the vec has one element and `(after ["TOK1" "TOK2"])` when it has more.
- [x] 2.3 Update the `Arbitrary` impl for `Tail` (`crates/core/src/arbitrary_impls.rs` if applicable) to generate non-empty token vectors.
- [x] 2.4 Update any other exhaustive `match` arms on `Tail::AfterToken` across the workspace until `cargo check` passes.

## 3. Parser DSL

- [x] 3.1 In `crates/config/src/parser_form.rs`, accept `(after STR)` (parses to `vec![STR]`) and `(after [STR…])` (parses to the bracket-list contents). Keep error messages descriptive.
- [x] 3.2 Reject `(after [])` at parse time with an error explaining at least one token is required.
- [x] 3.3 Reject non-string elements inside the bracket list with a clear error.
- [x] 3.4 Update `crates/config/src/canonicalise.rs` to canonicalise the single-element vector to the bare-string form during pretty-printing.

## 4. Engine semantics

- [x] 4.1 Update `split_outer_tail` in `crates/engine/src/eval/entry.rs` to find the first occurrence of any token in the `Tail::AfterToken` vec and split there.
- [x] 4.2 Update `evaluate_tail_authorise_fold` in `crates/engine/src/eval/effects.rs` so that when `ctx.parser.tail.is_some()` and `split.tail.is_none()` it returns `effect_arg_match(false, …)` (no-match) instead of falling back to `ctx.args`.
- [x] 4.3 Verify that the `(tail (authorise))` fallback to full argv still applies when `ctx.parser.tail.is_none()` (the existing rule-level recursion idiom).

## 5. Prelude

- [x] 5.1 Add `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))` to `crates/config/src/prelude.lisp`.
- [x] 5.2 Verify that `crates/config/src/prelude.rs` (or whichever module loads the prelude) handles the multi-token form without changes; if not, update accordingly.
- [x] 5.3 Add a unit test confirming the resolved parser for `nix` (in a config that omits a `(parser "nix" …)` declaration) has `Tail::AfterToken(vec!["--command", "-c"])`.
- [x] 5.4 Add a unit test confirming a user `(parser "nix" (tail (after "--command")))` declaration shadows the prelude.

## 6. Migration

- [x] 6.1 Update `crates/config/src/migrate/strip_redundant_boundary.rs` to read the prelude's `Tail::AfterToken(Vec<String>)` and strip a positional literal matching any token in the set.
- [x] 6.2 Add a unit test for `strip_redundant_boundary` covering the multi-token nix case (input: `(rule "nix" (when (positional (or "shell" "develop") "--command") (tail (authorise))))`; expected output: positional pattern with `"--command"` removed).
- [x] 6.3 Update the `wrapper_nix_shell_develop` regression test in `crates/config/src/migrate/regression_tests.rs` to expect the stripped form: `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`.
- [x] 6.4 Confirm no other regression tests in `regression_tests.rs` are impacted by the prelude addition.

## 7. Documentation

- [x] 7.1 Update REFERENCE.md prelude scope note to cover wrapper tools that are silent-bypass footguns.
- [x] 7.2 Document the multi-token `(tail (after [STR…]))` form in REFERENCE.md alongside the existing single-token form, with the nix example.
- [x] 7.3 Add a paragraph to the `(tail (authorise))` section of REFERENCE.md describing the no-match-on-missing-boundary semantics.

## 8. Verification

- [x] 8.1 Run `cargo fmt` and `cargo build`.
- [x] 8.2 Run `cargo test --workspace`.
- [x] 8.3 Run `cargo tarpaulin` per CLAUDE.md and inspect `lcov.info` for newly uncovered branches; add proptests or unit tests for any gaps in the changed engine and migration paths.
- [x] 8.4 Run `may-i eval 'nix shell nixpkgs#hello --command mkfs /dev/sda'` against the user's real config (`~/.config/nix-configuration/home/config/programs/may-i/config.lisp`) after re-running `may-i fmt` on it; verify the result is deny (matches the `mkfs` rule via tail recursion).
- [x] 8.5 Run `may-i eval 'nix shell nixpkgs#hello'` against the same config and verify it still resolves to allow (no boundary token, falls through to blanket allow).

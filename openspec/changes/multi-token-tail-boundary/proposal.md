## Why

Wrapper tools like `nix shell` and `nix develop` accept their inner-command boundary token under multiple spellings (`--command` and `-c`). The current `Tail::AfterToken(String)` accepts only one spelling, so users either mis-declare the boundary or fall back to broken `(positional … "--command")` patterns that silently never match (GNU parsing strips long flags from positionals). The migration of v1 `(wrapper "nix" … (flag "--command" :command+args))` produces such a broken rule, and `nix shell pkg --command mkfs /dev/sda` is currently allowed in user configs that intended to recurse into the inner command. Compounding this, when a parser declares a tail but the boundary token is absent in argv, `(tail (authorise))` falls back to recursing on the full argv rather than returning no-match — a silent footgun for any rule that gates recursion on the boundary's presence.

## What Changes

- Extend `Tail::AfterToken` from a single token to a set of tokens; the engine splits at the first occurrence of any listed token. **BREAKING** for any out-of-tree code that exhaustively matches `Tail::AfterToken(String)`.
- DSL: accept `(tail (after STR))` (existing single-token shorthand) and `(tail (after [STR…]))` (alias-set). Reject `(tail (after))` (empty) at parse time.
- Tighten `(tail (authorise))` semantics: when the parser declares a tail and `split.tail` is `None` (boundary token absent in argv), return no-match instead of falling back to full argv. Preserve the existing fallback only when the parser declares no tail at all.
- Add a `nix` parser to the prelude declaring `(tail (after ["--command" "-c"]))`, with `style gnu`. Update REFERENCE.md prelude-scope note to cover wrapper tools whose argv semantics are silent-bypass footguns.
- Update `strip_redundant_boundary` migration pass to strip positional literals matching any token in the prelude-declared tail set.
- Update `wrapper_nix_shell_develop` migration regression test to expect the stripped form.

## Capabilities

### New Capabilities

- `wrapper-tail-recursion`: declarative parser-level boundary specification for wrapper tools (`(tail (after …))` syntax + multi-token alias sets) and the engine semantics that govern when `(tail (authorise))` produces a recursive decision vs. no-match. Covers the prelude-shipped wrapper parsers (sudo, env, nix, …) as the canonical surface area.

### Modified Capabilities

- `migration-system`: the v1 → v2 migration of `(wrapper PROG … (flag "TOK" :command+args))` SHALL produce a rule whose positional pattern excludes `TOK` when the prelude declares `TOK` as a boundary token for `PROG`. This is a requirement change because the migration's prior output for nix is functionally incorrect under the current engine.

## Impact

- `crates/core/src/ast.rs`: `Tail::AfterToken(String)` → `Tail::AfterToken(Vec<String>)`. Display, arbitrary, and any exhaustive `match` arms updated.
- `crates/config/src/parser_form.rs`: parse variadic / alias-list form for `(after …)`.
- `crates/config/src/canonicalise.rs`: render single-token compactly, multi-token as alias-list.
- `crates/config/src/prelude.lisp` + `crates/config/src/prelude.rs`: ship `nix` parser entry.
- `crates/config/src/migrate/strip_redundant_boundary.rs`: iterate prelude tail-token set.
- `crates/config/src/migrate/regression_tests.rs`: update `wrapper_nix_shell_develop` expected output.
- `crates/engine/src/eval/entry.rs`: `split_outer_tail` searches for first occurrence of any listed token.
- `crates/engine/src/eval/effects.rs`: `evaluate_tail_authorise_fold` returns no-match when parser declares tail but boundary is absent.
- REFERENCE.md: scope note + multi-token tail documentation.
- User configs: re-running `may-i fmt` strips broken `"--command"` literals from migrated nix rules; no manual edit required.

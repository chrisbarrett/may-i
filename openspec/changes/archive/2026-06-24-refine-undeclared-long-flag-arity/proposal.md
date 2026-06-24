## Why

When a `--long` flag has no parser declaration and no rule references it as a
`(parameter …)`, the gnu tokeniser guesses its arity by **always** consuming the
next token as a value. That guess silently swallows the following flag, the `--`
flag-stop, or a subcommand — corrupting the positional residual that `(positional
…)` Patterns match against, and feeding the corruption straight into decisions.
It surfaced as a spurious `ask` on `cargo run --quiet --bin may-i -- …` (`--quiet`
ate `--bin`), and it had been silently degrading `cargo --release build` to `ask`
in stock configs with nobody noticing — because `ask` reads as safe.

This also sits in tension with `parser-bindings`, which states that under
`permute` the *remaining* (undeclared) tokens form the positional residual — yet
today an undeclared long flag consumes one of them.

## What Changes

- **Refine the arity guess (C′).** Under gnu-shaped styles, an undeclared long
  flag SHALL consume the next token as its value only when that token is a
  plausible value — i.e. **not** itself flag-shaped and **not** the `--`
  flag-stop. Declared parameters keep eating their next token regardless (the
  author asserted the arity); a flag declared as a boolean `(flag …)` is
  treated as value-less and never consumes its successor (so declaring the flag
  is the mitigation for the trailing-boolean-before-subcommand case).
  Negative-number tokens (`-5`) remain plausible values, not flags.
- **Never consume `--` (C′).** The `--` flag-stop SHALL never be absorbed as a
  flag value, so its terminator semantics always hold.
- **Surface the residual guess as an Advisory (B).** When the heuristic still
  has to guess — an undeclared long flag immediately followed by a non-flag
  token — evaluation SHALL emit an Advisory in the Trace naming the flag and the
  consumed token, so an invisible guess becomes an observable one. No decision
  changes from the advisory itself.
- **Document the parser-body declarations and the guard guidance (A).** The
  `may-i reference` output SHALL present `(flag NAME)` and `(parameter NAME …)`
  as parser-body declaration kinds (today only shown as rule-body matchers), and
  SHALL note that security deny-guards belong on `(flag …)` / `(anywhere …)`
  (which scan raw argv and are immune to arity guessing) rather than on
  `(positional …)` (which matches the consumption-sensitive residual).

> Not trust-relevant by the integrity definition (it changes no rule
> participation, approval, or hashing), but it re-tokenises some commands, so a
> few existing configs may see a decision shift — a release-note item, not a
> config migration.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `patterns` (bucket: parsing): refine how the gnu tokeniser computes the
  positional residual for **undeclared** long flags — the value-shape guard, the
  `--` protection, and the requirement that the residual guess be surfaced as an
  Advisory rather than applied silently.

## Impact

- **Code**: `crates/engine/src/eval/entry.rs` (`parser_positional_indices` /
  `parser_positional_args` / `first_positional_index` — the
  `gnu_long_consumes_next` consume decision plus the value-shape guard);
  `crates/core/src/ast.rs` (`flag_token_matches`, so a declared `(flag …)`
  suppresses the guess); a new `arity_guess_advisory` fold hook threaded
  through `ComposedFold` and the Trace producer (`traces`) and renderers
  (`output-rendering`); reference text in `REFERENCE.md` (embedded via
  `src/cmd_help.rs`).
- **Behaviour**: commands containing undeclared long flags re-tokenise. The fix
  direction is mostly `ask → allow` (structure restored); a narrow case (a
  trailing undeclared boolean before a guarded `(positional …)`) can shift the
  other way — mitigated by the A guidance to keep deny-guards on `(flag)` /
  `(anywhere)`. Capture in release notes.
- **Tests**: proptests over argv shapes (flag-then-flag, flag-then-`--`,
  flag-then-value, negative-number value); embedded `(check …)` cases; a
  regression for the `cargo --quiet`/`--release` reproductions.
- **No config-syntax change** → no migration file; `.may-i.lisp`'s `cargo`
  parser workaround can later be simplified but is not required to change.

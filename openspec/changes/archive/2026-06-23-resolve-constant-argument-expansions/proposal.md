## Why

`may-i` already resolves a **command-name** word against the command's
provably-constant variables (`BIN=./x; $BIN foo` evaluates `./x`), but argument
words are never resolved. So idiomatic straight-line scripts that build an
argument from local literals —

```sh
BUCKET=tracksuit-management-ap-southeast-2-tf-state
KEY=management/global/cross-account-iam-roles/terraform.tfstate
aws s3 cp "s3://$BUCKET/$KEY" /tmp/x
```

— hit `unresolved shell expansion in `s3://$BUCKET/$KEY` cannot satisfy an allow
rule` and ask, even though the value is provably constant. The pieces already
exist (`constant_env`, `Word::resolve`); only the link from argument words to
that env is missing. A spurious ask on ordinary bash trains reflex-approval —
the exact failure mode `may-i` exists to prevent.

## What Changes

- Resolve an **argument** word against the command's provably-constant env
  before matchers see it. When every expansion in the word resolves to a static
  literal, matchers see the resolved value and the word no longer floors an
  `:allow` as an unresolved expansion. A word with any unresolved part stays
  expansion-bearing and floors exactly as today (all-or-nothing per word).
- Close a latent **use-before-assignment** soundness gap. The existing
  command-name requirement already mandates the assignment "executes
  unconditionally before the use", but `constant_env` records assignments
  without tracking use position, so `cmd $X; X=lit` can mis-resolve `$X`. Make
  the provably-constant analysis use-order-aware so a variable used before its
  sole assignment is **not** resolved. This hardens the existing command-name
  path and is a precondition for sound argument resolution.
- Resolution only ever **narrows** asks: an unproven value is never resolved, so
  no decision that did not already rest on an unresolved expansion can change.

## Capabilities

Bucket: `parsing` (how argv words resolve before rules see them).

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: extend provably-constant resolution from the
  command-name word to argument words (all-or-nothing per word; an unresolved
  part keeps the word expansion-bearing), and tighten the provably-constant
  definition so a variable used before its sole assignment is not resolved
  (use-order-awareness), governing both the command-name and argument paths.

## Impact

- `crates/shell-parser/src/const_env.rs` — make `constant_env` use-order-aware:
  a name used before its sole qualifying assignment is disqualified. Default
  behaviour for straight-line assign-then-use is unchanged.
- `crates/engine/src/eval/decompose.rs` — in `decompose_simple_command`, resolve
  each argument word against `const_env`; when the word resolves fully to a
  literal, feed the resolved value into `args` and clear its `arg_expansions`
  entry (provable). Partially-resolved words keep their raw form and stay
  flagged.
- Tests: `crates/shell-parser` (use-order disqualification) and `crates/engine`
  (argument resolution narrows the unresolved-expansion floor; partial
  resolution still floors; metamorphic: resolved-arg classification equals the
  literal-arg classification).
- No DSL, config, or trust-hash surface change; no migration (the analysis is on
  internal AST types, not user config). Independent of the two in-progress
  substitution changes (different code paths).

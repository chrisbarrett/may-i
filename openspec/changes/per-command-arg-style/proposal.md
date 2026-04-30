## Why

A single hard-coded GNU-ish convention (`expand_combined_flags` +
`positional_args` in `crates/engine/src/eval/entry.rs`) governs how every
command's argv is split into flags, flag values, and positional arguments.
This default is wrong for several large families of CLI tools:

- **Single-dash-long** tools (`find`, `go`, `java`, `terraform`) — the parser
  splits `-name` into `-n -a -m -e`. A rule like `(forbidden "-n")` then
  fires falsely against any `-name X` argument.
- **GNU tools with value-bearing short flags** (`kubectl -n NS`, `bash -c CMD`)
  — `positional_args` strips `-n`/`-c` but leaves the value `NS`/`CMD` floating
  in the positional stream. Rules expecting `(positional "get" "pods")`
  silently fail when the user types `kubectl -n foo get pods`.
- **Legacy bundled** tools (`tar xvzf archive.tgz`, `ps aux`) — first-token
  flag clusters without a leading dash are treated as positional verbs.
- **Key=value** tools (`dd if=foo of=bar bs=1M`) — every token is positional;
  no flag/positional split happens at all.

A program-wide declaration that selects the appropriate tokenisation profile
fixes the false-positive and silent-mismatch classes of bug, and lays the
foundation for finer-grained per-rule flag patterns (separate proposal:
`flag-and-parameter-patterns`).

## What Changes

- **New top-level form** `(args-style PROGRAM PROFILE [overrides])` — declares
  how a program's argv is tokenised into flags, flag values, and positionals.
- **Profile values**:
  - `:gnu` — current behaviour: `--long`, short flags combine, `--long=val`
    or `--long val`. (Default when no `args-style` declared.)
  - `:single-dash-long` — every `-foo` is a long flag; no combining, no `--`
    prefix variant.
  - `:legacy-bundle` — first non-dashed alphanumeric cluster is a flag bundle
    (`tar xvzf …`); thereafter `:gnu` rules apply.
  - `:key-value` — tokens of the form `key=value` are recognised as
    flag-equivalent; all other tokens are positional.
- **Override**: `:flags-with-values (FLAG ...)` — declares additional flags
  that consume the next arg as their value. Composes with any profile.
- **Tokeniser rewrite** — `expand_combined_flags` and `positional_args` become
  profile-aware. Both functions accept a `Convention` derived from the
  current command's `args-style`.
- **Convention lookup** — at evaluation entry, the tokeniser looks up the
  current command's profile from a config-side table built from
  `args-style` declarations. Unknown commands default to `:gnu`.
- **Recursion via `(may-i ...)`** — the inner command's convention applies to
  the inner argv (lookup is by `ctx.command`, which already swaps on
  recursion).
- **Baseline shipped table** (optional but recommended): default
  `args-style` declarations for common single-dash-long tools (`find`,
  `terraform`, `go`) loaded automatically unless the user overrides.

## Capabilities

### New Capabilities

- `arg-tokenisation`: argv tokenisation profile per program; how raw shell
  tokens become annotated flag/value/positional streams.

### Modified Capabilities

- None directly; `pattern-expressions` and `partial-pattern-matching` continue
  to operate on the (now profile-aware) annotated stream without textual
  changes to their existing requirements.

## Impact

- `crates/core/src/ast.rs` — new top-level config form `ArgsStyle { program,
  profile, flags_with_values }` and a `Convention` value type.
- `crates/config/src/...` — parser support for `(args-style …)`, validation,
  duplicate detection (last declaration wins, with a warning).
- `crates/engine/src/eval/entry.rs` — `expand_combined_flags` and
  `positional_args` accept a `&Convention` and behave per profile.
- `crates/engine/src/eval/effects.rs` — call sites pass through the resolved
  convention.
- `crates/engine/src/eval/context.rs` (or new module) — convention lookup by
  command name.
- `tests/` — new integration tests covering each profile's expected
  tokenisation against representative inputs (find, kubectl, tar, dd).
- `crates/engine/src/test_generators/` — property tests: profile is
  deterministic; `:gnu` profile preserves all existing behaviour.
- `openspec/specs/arg-tokenisation/spec.md` — created by this change.

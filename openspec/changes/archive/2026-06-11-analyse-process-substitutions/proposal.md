## Why

Process substitutions (`<(…)`, `>(…)`) are mishandled by the parser, with two
consequences — one a coverage hole, one a silent under-analysis:

1. **The inner command escapes analysis entirely.** `cat <(rm -rf /danger)`
   parses to just `cat`; the `rm -rf /danger` inside the substitution never
   appears in the AST and is never evaluated. A dangerous command hidden in a
   process substitution bypasses `may-i` completely — including in redirect
   position (`… < <(rm -rf /danger)`).
2. **A loop redirected from a process substitution swallows the rest of its
   enclosing compound.** `f() { while read x; do …; done < <(find .); rm -rf
   /danger; }` drops both the `find` and the trailing `rm -rf /danger`, emitting
   only a Warning-severity `MissingClosingKeyword`. Warnings do not floor the
   decision, so the `rm` vanishes with no signal. Confirmed against the
   motivating real-world script (terragrunt stack hashing).

The trigger is process-substitution-specific: a command-substitution redirect
target (`< "$(…)"`) parses correctly and keeps following commands. Both bugs
let real commands escape the authorisation `may-i` exists to provide.

## What Changes

- Parse `<(…)` / `>(…)` as a first-class process substitution in both argument
  position and redirect-target position, capturing the inner command and
  stopping at the matching `)`.
- Extract and evaluate the **inner command** of a process substitution as an
  embedded command, so a dangerous command inside `<(…)` is authorised like one
  inside `$(…)`.
- Parsing a process substitution SHALL NOT consume tokens past its closing `)`;
  commands following a `done < <(…)` redirect inside a brace group, subshell, or
  function body SHALL remain in the command and be evaluated.
- Backstop: if a construct still cannot be placed, emit an Error-severity
  diagnostic (floor to `:ask`) rather than silently dropping tokens — the same
  no-silent-loss principle as `command-position-reserved-words`.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add requirements that a process substitution's
  inner command is extracted and evaluated wherever the substitution appears,
  and that process-substitution parsing never consumes following tokens or
  silently drops commands.

## Impact

- `crates/shell-parser` — process-substitution lexing/parsing in argument and
  redirect-target position; disambiguate `< <(…)` (input redirect + procsub)
  from `< (subshell)`; ensure the parser resumes after the matching `)`.
- `crates/engine/src/eval/decompose.rs` — emit an embedded unit for a process
  substitution's inner command (procsub keeps its existing unnamed-reason form).
- Tests: `crates/shell-parser` parse/AST cases + `crates/engine` eval scenarios.
- No DSL, config, or trust-hash surface change; no migration. Out of scope:
  connecting the substituted FD to the consuming command's dataflow.

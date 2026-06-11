## Why

Two shell-parse gaps make `may-i` misjudge ordinary commands. A leading
pipeline negation (`! kill -0 %1`) is parsed as a command literally named `!`,
so no rule matches and the inner command escapes coverage. And an unterminated
command substitution (`grep "…$(…" f`) is recursed into as if its swallowed
tail were a real command, surfacing `No rule for command `|deciding|…`` instead
of the parse-error reason the spec already mandates. Both read to the user as
"`may-i` parses badly", eroding trust in the tool that gates their shell.

## What Changes

- Recognise a leading `!` as **pipeline negation** in the shell grammar: the
  inner pipeline is evaluated as if `!` were absent, and `!` never becomes a
  command name. Negation is authorisation-transparent — `may-i` decides on
  command structure, not exit status, so `! rm -rf /` still evaluates `rm`.
  Handled at pipeline-start position only, so `!` as an argument (`find . !
  -name x`, `[ ! -f x ]`) stays literal.
- Stop fabricating an inner command from an **unterminated** substitution. When
  a `$(…)` / `` `…` `` / `${…}` region carries an Error-severity diagnostic, its
  swallowed text is not a command; the evaluator SHALL NOT recurse into it. The
  existing Error-diagnostic floor then owns the outcome, so the reason conforms
  to the already-specified `parse error: <kind> at line L, column C: '<excerpt>'`
  form instead of a invented `No rule for command …` clause.
- Add regression coverage for both as proptests/unit scenarios.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that leading `!` is
  pipeline negation (transparent, never a command name); add scenarios under the
  existing "Error-severity diagnostics floor decision at ask" requirement
  asserting that an unterminated substitution is not recursed into and that the
  floor reason — not a fabricated `No rule for command …` — is reported.

## Impact

- `crates/shell-parser/src/parse.rs` — consume a leading bare-`!` word in
  `parse_pipeline` as a negation prefix (parse-level, position-aware; lexer
  unchanged so `!`-as-argument is untouched).
- `crates/engine/src/eval/command.rs` — in `decompose`, suppress the
  `EmbeddedCommand` unit for a substitution whose span coincides with an
  Error-severity diagnostic; leaves the best-effort AST unchanged.
- Tests: `crates/shell-parser` and `crates/engine` proptests + unit scenarios.
- No DSL, config, or trust-hash surface change; no migration required.

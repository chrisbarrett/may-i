## Why

When the shell parser hits an error-severity diagnostic (unterminated quote,
backtick, command substitution, …), the engine floors the decision at `:ask`
and emits the reason `"parse error: ambiguous command boundary"`. That string
is what the Claude Code hook surfaces as `permissionDecisionReason`, and what
`may-i eval` prints as the headline reason.

The string is unhelpful to the primary consumer of the hook surface: the agent
that has to reformulate the rejected command. It names neither the diagnostic
kind, nor the location, nor the offending fragment — even though the engine
already has all of that information in `EvalResult.parse_diagnostics`. Today
the agent must blindly retry; with a specific reason it can target the actual
defect.

## What Changes

- Replace the literal `"parse error: ambiguous command boundary"` at the two
  call sites in `crates/engine/src/eval/command.rs` with a formatted message
  derived from the first error-severity `ParseDiagnostic`, kept under the
  same `"parse error: "` prefix.
- Add a source-aware formatter on `ParseDiagnostic` in
  `crates/shell-parser` that produces a one-line string of the form
  `<kind message> at line L, column C: <excerpt>` — line/column 1-based,
  excerpt windowed around `span.start` with control characters escaped and
  truncated content ellipsised.
- Cascading diagnostics are ignored — only the first error-severity entry
  drives the reason. Full diagnostic vector remains available via
  `EvalResult.parse_diagnostics` for the CLI rich path.
- Tests and the affected requirement in `shell-command-security-model`
  update to assert the new shape.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `shell-command-security-model`: the "Error-severity diagnostics floor
  decision at ask" requirement strengthens its reason-content contract from
  "SHALL mention the parse diagnostic" to a concrete shape (kind + line +
  column + excerpt, single diagnostic).

## Impact

- `crates/shell-parser`: add `ParseDiagnostic::format_with_source(&self, src: &str) -> String`.
- `crates/engine/src/eval/command.rs`: two reason literals replaced; both
  aggregate sites consume the first error-severity diagnostic.
- `src/cmd_claude_code_hook.rs`: no code changes — surfaces the engine's
  improved `reason` automatically via `permissionDecisionReason`.
- `src/cmd_eval.rs`: no code changes — pretty / JSON output already
  carries the full `parse_diagnostics` array; headline reason improves
  for free.
- Tests under `crates/engine/src/eval/`, `tests/`, and any snapshot that
  pins the old reason text need updating.
- No DSL or config schema changes. No migration required.

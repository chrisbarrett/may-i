## Why

When a backtick or `$(…)` command substitution inside an outer command bubbles
up an `:ask` decision, the reason shown to the harness names only the inner
command (e.g. ``No rule for command `:rebuild` ``). The user sees a colon-prefixed
token detached from any visible invocation and has to puzzle out why the harness
is asking about it. The real cause — that an outer command (often `grep`,
`echo`, etc.) contains a substitution that bash will execute — is hidden.

Real-world trigger: an agent wrote
``grep -nE "…|`:rebuild`(?!-fn)" spec.md``. Bash will run `:rebuild` because
backticks inside `"…"` are command substitution. `may-i` correctly flagged the
embedded command, but the prompt did not tell the operator the offending
backticks came from an unquoted regex in `grep`.

## What Changes

- When a rule body decision (the strictest decision shown to the harness)
  originates from an embedded command substitution, the reason SHALL identify
  the outer command and the substitution form (`` `…` `` or `$(…)`).
- The annotation applies only to bubbled-up reasons; reasons that already
  describe the top-level invocation are unchanged.
- The annotation appears in the single-line reason returned through the Claude
  Code hook surface; the structured `SegmentDecision` stream is unaffected.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `rule-decisions`: extend the "No rule for the program" / "Rules exist but no
  body matches" reasons so that embedded-substitution origins name the outer
  command.

## Impact

- `crates/engine/src/eval/command.rs` — `evaluate_command_inner` builds the
  aggregate reason; it needs to wrap the inner reason with origin info when the
  contributing unit is an `EmbeddedCommand`.
- `crates/engine/src/eval/decompose.rs` — `EvalUnit::EmbeddedCommand` may need
  to carry the substitution form (backtick vs `$(…)`) and the outer command
  name so the wrapping layer can format the annotation.
- No change to the hook JSON schema; only the `permissionDecisionReason`
  string content changes.
- Snapshot tests covering reasons need refresh.

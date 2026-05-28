## Why

Codex (codex-cli) wires `may-i` as a `PreToolUse` hook the same way Claude Code
does, but Codex's hook parser rejects `permissionDecision: "ask"` as an
unsupported value. Every `ask` from `may-i` is therefore logged as a hook
failure and the command falls through to Codex's default behaviour with no
signal carried across. The transport is structurally compatible; only the
response shape for the `ask` decision differs.

## What Changes

- Detect the Codex harness from the presence of the `turn_id` field in the
  stdin JSON payload at hook entry and select a Codex profile in place of the
  default Claude Code profile.
- Under the Codex profile, emit hook output for `ask` that omits
  `permissionDecision` / `permissionDecisionReason` and surfaces the reason via
  `additionalContext` instead. `allow` and `deny` map 1:1 — same envelope.
- Insert `:client/codex` (presence) into the context facts under the Codex
  profile, replacing the `:client/claude-code` fact that the default profile
  inserts.
- The default (Claude Code) hook output is unchanged.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `harness-integration`: add a Codex hook adapter alongside the existing
  Claude Code adapter, including the profile-selection rule, the
  `:client/codex` fact, and the Codex-specific response shape for `ask`.

## Impact

- Affected code: `src/cmd_claude_code_hook.rs` (renamed/extended to a generic
  hook entry that selects a profile), `src/output/render.rs`,
  `src/output/trust_block.rs`, `src/main.rs` (dispatch).
- New payload field consumed: `turn_id` (presence-only) at hook entry.
- New context fact key: `:client/codex`.
- No DSL changes. No trust-store changes. No migration needed.

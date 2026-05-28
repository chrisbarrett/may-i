## Context

Hook mode is currently a single code path that assumes the Claude Code hook
protocol. `src/main.rs:185` dispatches to `cmd_claude_code_hook` when no
subcommand is supplied and stdin is not a TTY; that module reads the JSON
payload, builds `ContextFacts` keyed under `:client/claude-code` /
`:claude-code/*`, calls `pipeline.run_hook`, and the pipeline calls
`output::render_hook` (or `render_hook_trust_block` on a trust block).

Both renderers emit the same envelope shape:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
                        "permissionDecision": "<allow|ask|deny>",
                        "permissionDecisionReason": "<reason>"}}
```

`codex-rs/hooks/src/schema.rs` accepts the same three decisions on the wire,
but `codex-rs/hooks/src/engine/output_parser.rs` short-circuits `Ask` with
`"PreToolUse hook returned unsupported permissionDecision:ask"`; the parent
hook record is marked `Failed` while `should_block` stays false, so the
command proceeds but every `ask` decision lands in the Codex hook log as an
error. `allow` and `deny` are accepted as-is.

The Codex hooks reference (https://developers.openai.com/codex/hooks)
documents `turn_id` as a Codex-specific extension delivered in the stdin
payload for every turn-scoped event (PreToolUse, PermissionRequest,
PostToolUse, UserPromptSubmit, SubagentStop, Stop). Claude Code's
PreToolUse payload has no `turn_id` field. Other payload fields
(`session_id`, `transcript_path`, `cwd`, `hook_event_name`,
`permission_mode`, `tool_name`, `tool_input`, `tool_use_id`) overlap
between the two harnesses, so `turn_id` is the only contractual
single-bit discriminator we can rely on.

`CODEX_HOME` is **not** suitable as a detection signal even though Codex
reads it: it is user-configured (defaulting to `~/.codex` when unset),
Codex itself does not set it for subprocesses, and Codex's
`shell_environment_policy` can strip it before the hook runs. Wrappers
like promptfoo's Codex provider already filter it from the inherited
environment.

The Codex hook output schema treats `additionalContext` as agent-visible
context that Codex threads back into the model on the next turn, which is the
right surface for the reason behind an `ask` that Codex itself will translate
into its `approval_policy` flow.

## Goals / Non-Goals

**Goals:**

- Eliminate the "unsupported permissionDecision:ask" log noise under Codex.
- Preserve the existing claude-code hook output bit-for-bit when run outside
  of Codex.
- Make the harness-profile selection a single, explicit decision at hook
  entry; no scattered checks downstream.
- Let rules condition on the active harness via `(fact? :client/codex)` in
  the same way `:client/claude-code` already works.

**Non-Goals:**

- No new subcommand. The hook entry stays argument-less, dispatched by
  `main.rs` when stdin is not a TTY.
- No payload-shape sniffing fallback. If `CODEX_HOME` is unset, we use the
  Claude Code profile.
- No changes to `may-i eval` / `may-i check` output. Hook mode only.
- No new DSL forms, no trust-store impact, no migration.

## Decisions

### 1. Introduce a `HarnessProfile` enum, selected at hook entry

Add an enum in the hook module — two variants, `ClaudeCode` and `Codex` —
chosen by inspecting the parsed stdin JSON: when the payload object has a
`turn_id` key, select Codex; otherwise Claude Code. Presence-only test; the
value is not inspected (it is an opaque ID).

The profile is selected once after JSON parsing, threaded through
`run_hook` as a parameter, and `render_hook` / `render_hook_trust_block`
branch on it.

**Alternative considered — `CODEX_HOME` env var:** rejected. The variable
is user-controlled (defaulting to `~/.codex` if unset), not set by Codex
itself, and may be filtered by `shell_environment_policy` or by harness
wrappers before reaching the hook subprocess. It is documented as a
discovery path, not a harness signal.

**Alternative considered — `model` or `transcript_path` payload field:**
rejected. Claude Code's PreToolUse payload also carries these fields;
the docs only mark `turn_id` as a Codex-specific extension.

**Alternative considered — plugin env vars (`PLUGIN_ROOT`,
`CLAUDE_PLUGIN_ROOT`):** rejected. Set only for plugin-bundled hooks,
not for user-configured hooks like the may-i wiring. `CLAUDE_PLUGIN_ROOT`
is also intentionally set by Codex for Claude-plugin compatibility, so
it would false-positive.

**Alternative considered — separate subcommand `may-i codex-hook`:**
rejected. The harness wiring is a single binary path
(`${cfg.package}/bin/may-i`) under `programs.codex.settings.hooks.PreToolUse`
in the nix module; adding a subcommand requires changing the wrapper and
breaks the "drop-in, no arguments" property both harnesses currently rely
on.

### 2. Codex `ask` response shape

Under Codex, when the evaluation result is `ask`, emit:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
                        "additionalContext": "<reason>"}}
```

— no `permissionDecision`, no `permissionDecisionReason`. When the reason
is empty/absent we omit `additionalContext` too, emitting just
`{"hookSpecificOutput": {"hookEventName": "PreToolUse"}}`.

`allow` and `deny` keep the existing envelope (Codex accepts both).

**Alternative considered — `systemMessage`:** rejected. `systemMessage` is
hook-log-only; the reason is the part most useful to the agent's next turn,
and `additionalContext` is what threads it through.

**Alternative considered — omit reason entirely:** rejected. Loses the
"why" signal that the user authored in the rule.

### 3. Client fact: `:client/codex`

Under the Codex profile insert `:client/codex` (presence) and the same
secondary keys the Claude Code profile carries, namespaced under
`:codex/` — `:codex/permission-mode`, `:codex/cwd`, `:codex/tool-name`,
`:codex/hook-event-name` — populated from the corresponding payload fields
when present. We do **not** insert `:client/claude-code` simultaneously;
exactly one harness fact is live per invocation.

This mirrors the existing convention in `src/cmd_claude_code_hook.rs:64-90`
and matches the harness-integration spec's "client and tool facts"
requirement.

### 4. Module split

Rename `src/cmd_claude_code_hook.rs` → `src/cmd_hook.rs`. The dispatcher
selects the profile, extracts the command (shape is identical: `tool_name`
+ `tool_input.command`), and builds the appropriate `ContextFacts`. Profile-
aware rendering lives in `src/output/render.rs` and
`src/output/trust_block.rs` as additional functions / a profile parameter on
the existing ones.

**Alternative considered — keep two sibling modules:** rejected. The
payload-extraction logic is identical; only the fact-building and rendering
diverge. Two modules duplicate the extractor and obscure the single
profile-selection point.

## Risks / Trade-offs

- [Codex stops emitting `turn_id` in a future hook-schema revision] → we
  fall back to the Claude Code shape and Codex logs the `ask` rejection.
  Mitigation: `turn_id` is documented as a stable Codex-specific extension
  for all turn-scoped events; track the Codex hooks reference for schema
  changes. Cover both shapes with integration tests so a regression is
  visible in CI.

- [Codex changes its accepted decisions later] → response shape drifts. Low
  risk for `allow`/`deny` (industry-standard); `ask` shape is already
  bespoke. Mitigation: response construction is centralised in
  `render_hook`, single point of change.

- [Renaming `cmd_claude_code_hook.rs`] → minor churn in `main.rs` and tests.
  Mitigation: the module is small (one public function); rename and update
  the single dispatch site.

- [`additionalContext` interpretation by Codex changes] → reason disappears
  from the agent's context. Mitigation: spec the field's intended use and
  add an integration check; if Codex changes semantics we change the field,
  not the surrounding shape.

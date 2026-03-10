## Why

`may-i` can already evaluate context-sensitive rules, but it has no way to see which OpenCode agent invoked it when an OpenCode integration calls `may-i eval`. That makes it impossible to express policies such as stricter shell permissions for the `plan` agent while keeping `build` more permissive.

## What Changes

- Add runtime context ingestion for OpenCode when `may-i` is invoked from an OpenCode integration layer.
- Introduce a stable OpenCode-specific context fact for the active agent so rules can match `build`, `plan`, and future agents.
- Define how integration-provided OpenCode context should behave in `eval`, traces, and tests so policies remain inspectable and predictable.
- Document a minimal integration contract between OpenCode and `may-i`, including the recommended environment variable interface and any optional debugging override.

## Capabilities

### New Capabilities
- `opencode-context`: Expose OpenCode runtime facts, especially the active agent, to rule evaluation when `may-i` is called from OpenCode.

### Modified Capabilities

## Impact

- Affected code: OpenCode runtime context ingestion, `eval` command path, traces/JSON output, tests, and user-facing configuration examples.
- Affected integration: the current OpenCode-to-`may-i` call path will need to pass the active OpenCode agent to `may-i`.
- Dependencies: no new external service dependencies; only a small integration contract between OpenCode and `may-i`.

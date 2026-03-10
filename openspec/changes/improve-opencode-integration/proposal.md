## Why

The current OpenCode path relies on `MAYI_OPENCODE_AGENT` and other ambient environment hints, which makes policy inputs implicit and leaves hook-mode behavior split across one-off integration logic. We need a cleaner contract where integrations pass facts explicitly, while bare `may-i` hook mode still works zero-config by recognizing the calling harness from the payload it receives.

## What Changes

- Add explicit `may-i eval` fact flags so integrations can pass runtime facts such as `:client/opencode` and `:opencode/agent` directly instead of relying on `MAYI_OPENCODE_AGENT`.
- Change OpenCode handling so `OPENCODE=1` is only a routing hint for bare hook mode and never contributes policy facts on its own.
- Introduce harness adapters for Claude Code and OpenCode so both paths follow the same flow: parse payload, extract command plus explicit runtime facts, evaluate, and render the harness-specific response.
- Keep zero-config magic only in bare `may-i` hook mode by autodetecting the harness from payload shape, with tests and docs covering the new integration contract and migration away from the old environment variable path.

## Capabilities

### New Capabilities
- `harness-adapters`: Route bare hook-mode payloads through harness-specific adapters that detect the harness, extract explicit runtime facts, and render the correct response format.

### Modified Capabilities
- `opencode-context`: Replace the implicit `MAYI_OPENCODE_AGENT` contract with explicit eval facts and define how OpenCode facts behave in eval, hook routing, and traces.

## Impact

- Affected code: `eval` CLI argument parsing, hook-mode payload handling, harness-specific response rendering, shared evaluation plumbing, and end-to-end tests.
- Affected integrations: OpenCode callers must pass explicit facts to `may-i eval`; bare stdin hook mode continues to auto-route by harness payload shape.
- Affected docs: README examples and integration guidance must explain explicit fact flags, hook autodetection, and the limited role of `OPENCODE=1`.

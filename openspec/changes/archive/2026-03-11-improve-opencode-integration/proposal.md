## Why

The current OpenCode path relies on `MAYI_OPENCODE_AGENT`, which makes policy inputs implicit. At the same time, bare `may-i` hook mode is tightly coupled to Claude Code payloads and response formatting. We need a cleaner split: explicit facts for integrations such as OpenCode's custom bash tool today, and a harness-adapter architecture for the zero-config hook entrypoint that Claude Code already uses and future harnesses may use later.

## What Changes

- Add explicit `may-i eval` fact flags so integrations can pass runtime facts such as `:client/opencode` and `:opencode/agent` directly instead of relying on `MAYI_OPENCODE_AGENT`.
- Refactor bare `may-i` hook mode around harness adapters so Claude Code keeps its zero-config stdin/stdout flow and future harnesses can plug into the same shared evaluation pipeline.
- Keep OpenCode on the explicit `may-i eval --fact ...` path for now, matching the current custom bash tool integration instead of assuming native hook support.
- Keep zero-config magic only in bare `may-i` hook mode, with tests and docs covering the new explicit OpenCode contract and the generalized harness-adapter architecture.

## Capabilities

### New Capabilities
- `harness-adapters`: Route bare hook-mode payloads through harness-specific adapters that detect the harness, extract explicit runtime facts, and render the correct response format. Claude Code is the current supported harness; the adapter boundary exists so others can be added cleanly later.

### Modified Capabilities
- `opencode-context`: Replace the implicit `MAYI_OPENCODE_AGENT` contract with explicit eval facts and define how OpenCode facts behave in eval and traces.

## Impact

- Affected code: `eval` CLI argument parsing, hook-mode payload handling, harness-specific response rendering, shared evaluation plumbing, and end-to-end tests.
- Affected integrations: OpenCode callers must pass explicit facts to `may-i eval`; bare stdin hook mode continues to serve Claude Code and any future harnesses that adopt the adapter contract.
- Affected docs: README examples and integration guidance must explain explicit fact flags for OpenCode and the generalized harness-adapter structure for hook mode.

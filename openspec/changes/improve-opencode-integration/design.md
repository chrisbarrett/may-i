## Context

`may-i` currently has two separate integration paths. `may-i eval` reads `MAYI_OPENCODE_AGENT` from the environment and synthesizes OpenCode facts, while bare stdin hook mode is hard-coded around Claude Code payloads and response formatting. In practice, OpenCode does not currently expose native Claude-style hooks; the integration today happens through a custom bash tool that shells out to `may-i eval` before execution. That makes OpenCode policy input implicit, ties behavior to ambient shell state, and leaves no clean place to support more than one hook harness without copying evaluation logic.

This change moves the integration contract toward explicit runtime facts. Integrations that call `may-i eval` will pass facts on the CLI, and bare `may-i` hook mode will be reorganized around harness adapters so the existing Claude Code path stays zero-config while the architecture remains ready for future harnesses.

## Goals / Non-Goals

**Goals:**
- Let integrations pass runtime facts to `may-i eval` explicitly, including presence and scalar facts.
- Remove ambient OpenCode environment variables from the policy-input path.
- Refactor hook mode behind a harness-adapter boundary without changing Claude Code behavior.
- Keep evaluation, traces, and decision semantics identical once the command and facts are extracted.

**Non-Goals:**
- Introduce a new policy DSL or change how `(context ...)` rules work.
- Expand OpenCode metadata beyond the explicit facts already needed for agent-aware policies.
- Build a native OpenCode hook contract before OpenCode itself supports one.
- Require a new mandatory harness flag for normal bare hook-mode usage.

## Decisions

### Use repeatable `--fact` flags for explicit eval-time facts

`may-i eval` will accept a repeatable `--fact` flag. A value without `=` represents a presence fact such as `:client/opencode`; a value with `=` represents a scalar fact such as `:opencode/agent=plan`. These flags become the only supported way for direct `eval` callers to provide OpenCode runtime context.

This keeps the contract visible at the call site, works for both OpenCode and future integrations, and maps directly onto the existing `ContextFacts` model.

Alternatives considered:
- Keep `MAYI_OPENCODE_AGENT`: rejected because it hides policy input in ambient process state.
- Add separate flags for presence and scalar facts: rejected because one flag with a small grammar is easier to document and compose.
- Accept a JSON blob of facts: rejected because it is harder to type, test, and validate in shell integrations.

### Introduce harness adapters around a shared evaluation pipeline

Hook mode will be split into harness adapters that each know how to recognize a payload, extract the command and explicit runtime facts, and render the harness-native response. `cmd_hook` becomes a small coordinator: read stdin, parse JSON, choose an adapter, evaluate with shared logic, and print the adapter response.

This isolates harness-specific JSON details from the rest of the CLI while preserving the current Claude Code behavior. It also gives `may-i` a stable extension point for future harnesses, even though OpenCode currently integrates through explicit `eval --fact` calls rather than native hook payloads.

Alternatives considered:
- Keep adding `if` branches inside `cmd_hook`: rejected because payload parsing, context extraction, and response formatting would become harder to reason about as harnesses diverge.
- Push harness-specific logic into the engine: rejected because harness parsing is a CLI boundary concern, not a rule-evaluation concern.

### Detect hook harnesses from payload shape

Bare `may-i` hook mode will inspect the incoming payload shape to decide which adapter applies. Today that means preserving the existing Claude Code path while organizing the implementation so additional harnesses can be added without reworking evaluation and trace plumbing.

This preserves the desired zero-config ergonomics for stdin hook mode without reintroducing implicit policy input or inventing a speculative OpenCode hook contract.

Alternatives considered:
- Keep adding `if` branches inside `cmd_hook`: rejected because payload parsing, context extraction, and response formatting would become harder to reason about as harnesses are added.
- Require `--harness claude|...`: rejected because it adds friction to the common hook-mode path that can already be inferred from input.

### Preserve existing trace and decision behavior after fact extraction

Once a command and fact set are extracted, both `eval` and hook mode will continue to use the same engine entry points and trace rendering they use today. The refactor changes how runtime context is assembled, not how rules are matched or explained.

This limits the blast radius and keeps the change easy to verify with existing trace-oriented tests.

## Risks / Trade-offs

- [Integrations keep using `MAYI_OPENCODE_AGENT`] -> Update docs and tests to make `--fact` the only supported direct-eval contract.
- [The harness-adapter abstraction looks overbuilt with only Claude Code active today] -> Keep the adapter boundary thin and justify it as infrastructure for the already hook-based Claude path plus future integrations.
- [Malformed `--fact` values are hard to debug] -> Reuse existing fact-key validation rules and return actionable CLI errors.
- [Future harness behavior drifts from shared evaluation behavior] -> Keep adapters thin and cover each harness with end-to-end tests that assert the same decision and reason survive rendering.

## Migration Plan

- Add `--fact` parsing and switch OpenCode integration guidance from `MAYI_OPENCODE_AGENT` to explicit fact flags.
- Refactor hook mode behind harness adapters while preserving the existing Claude Code response contract.
- Keep OpenCode on the explicit `eval --fact` path for now, matching the custom bash tool integration.
- Remove or update tests and docs that currently describe ambient OpenCode environment variables as policy input.

## Open Questions

- Should `may-i` emit a targeted compatibility warning when `MAYI_OPENCODE_AGENT` is present, or should the old path simply stop affecting evaluation?
- When OpenCode eventually offers a native hook surface, what payload fields should its adapter treat as the authoritative source for agent/runtime metadata?

## Context

`may-i` currently has two separate integration paths. `may-i eval` reads `MAYI_OPENCODE_AGENT` from the environment and synthesizes OpenCode facts, while bare stdin hook mode is hard-coded around Claude Code payloads and response formatting. That makes OpenCode policy input implicit, ties behavior to ambient shell state, and leaves no clean place to support more than one harness without copying evaluation logic.

This change moves the integration contract toward explicit runtime facts. Integrations that call `may-i eval` will pass facts on the CLI, and bare `may-i` hook mode will keep the only remaining zero-config behavior by selecting a harness adapter from the incoming payload shape.

## Goals / Non-Goals

**Goals:**
- Let integrations pass runtime facts to `may-i eval` explicitly, including presence and scalar facts.
- Remove ambient OpenCode environment variables from the policy-input path.
- Support Claude Code and OpenCode hook payloads through a shared harness-adapter flow.
- Keep evaluation, traces, and decision semantics identical once the command and facts are extracted.

**Non-Goals:**
- Introduce a new policy DSL or change how `(context ...)` rules work.
- Infer policy facts from ambient environment state such as `OPENCODE=1`.
- Expand OpenCode metadata beyond the explicit facts already needed for agent-aware policies.
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

This keeps Claude Code and OpenCode behavior aligned while isolating harness-specific JSON details from the rest of the CLI.

Alternatives considered:
- Keep adding `if` branches inside `cmd_hook`: rejected because payload parsing, context extraction, and response formatting would become harder to reason about as harnesses diverge.
- Push harness-specific logic into the engine: rejected because harness parsing is a CLI boundary concern, not a rule-evaluation concern.

### Detect hook harnesses from payload shape, with `OPENCODE=1` only as a tie-breaker

Bare `may-i` hook mode will first inspect the incoming payload shape to decide which adapter applies. `OPENCODE=1` may be used only as a routing hint when payloads are otherwise ambiguous; it never creates `:client/opencode`, `:opencode/agent`, or any other policy fact by itself.

This preserves the desired zero-config ergonomics for stdin hook mode without reintroducing implicit policy input.

Alternatives considered:
- Route primarily from `OPENCODE=1`: rejected because it would again make policy-sensitive behavior depend on ambient environment.
- Require `--harness claude|opencode`: rejected because it adds friction to the common hook-mode path that can already be inferred from input.

### Preserve existing trace and decision behavior after fact extraction

Once a command and fact set are extracted, both `eval` and hook mode will continue to use the same engine entry points and trace rendering they use today. The refactor changes how runtime context is assembled, not how rules are matched or explained.

This limits the blast radius and keeps the change easy to verify with existing trace-oriented tests.

## Risks / Trade-offs

- [Integrations keep using `MAYI_OPENCODE_AGENT`] -> Update docs and tests to make `--fact` the only supported direct-eval contract.
- [Adapter detection becomes ambiguous] -> Use deterministic payload-shape matching, treat `OPENCODE=1` only as a tie-breaker, and fail with a clear diagnostic when no adapter matches.
- [Malformed `--fact` values are hard to debug] -> Reuse existing fact-key validation rules and return actionable CLI errors.
- [Claude Code and OpenCode responses drift from shared evaluation behavior] -> Keep adapters thin and cover both harnesses with end-to-end tests that assert the same decision and reason survive rendering.

## Migration Plan

- Add `--fact` parsing and switch OpenCode integration guidance from `MAYI_OPENCODE_AGENT` to explicit fact flags.
- Refactor hook mode behind harness adapters while preserving the existing Claude Code response contract.
- Add OpenCode hook fixtures that verify routing, fact extraction, and response rendering.
- Remove or update tests and docs that currently describe ambient OpenCode environment variables as policy input.

## Open Questions

- Should `may-i` emit a targeted compatibility warning when `MAYI_OPENCODE_AGENT` is present, or should the old path simply stop affecting evaluation?
- What exact OpenCode payload fields should the adapter treat as the authoritative source for agent/runtime metadata if multiple aliases are temporarily in play during migration?

## Context

`may-i` already supports namespaced context facts, but the current OpenCode integration invokes `may-i eval --json <command>` without passing any explicit runtime context. The integration layer does have access to the active agent, so the missing piece is an explicit contract between OpenCode and `may-i`.

This change is intentionally narrower than the earlier context-facts work. It does not add new DSL surface area; it extends runtime ingestion so policies can distinguish OpenCode `build`, `plan`, and future agents when commands are evaluated through an OpenCode integration.

## Goals / Non-Goals

**Goals:**
- Let an OpenCode integration pass the active agent to `may-i` in a stable, explicit way.
- Expose OpenCode runtime facts as namespaced context keys that work with the existing `(context ...)` DSL.
- Keep the integration conservative so ambient shell state does not accidentally make commands look like they came from OpenCode.
- Keep matching behavior inspectable in `eval` JSON output, traces, and tests.

**Non-Goals:**
- Infer the current OpenCode agent from undocumented OpenCode environment variables.
- Add a broader OpenCode session model such as session IDs, message IDs, or agent mode metadata in this change.
- Change hook-mode behavior for Claude Code beyond continuing to support existing runtime facts.
- Introduce a new config DSL for OpenCode-specific predicates.

## Decisions

### Use an explicit `MAYI_OPENCODE_AGENT` environment variable as the integration contract

The OpenCode integration will pass the active agent to the `may-i` subprocess via `MAYI_OPENCODE_AGENT=<agent>`. When present, `may-i` will treat that value as authoritative OpenCode context.

This keeps the integration local to the OpenCode call site, avoids depending on undocumented OpenCode runtime behavior, and does not require users to thread a new CLI flag through normal usage.

Alternatives considered:
- Reuse ambient `OPENCODE=1` or other OpenCode variables: rejected because they do not identify the active agent and may be present outside the integration-controlled call path.
- Add only a CLI flag such as `--opencode-agent`: rejected for the initial change because the integration already has a natural mechanism for structured subprocess context.
- Add both env var and CLI flag now: deferred to keep the contract small; a CLI override can be added later if debugging needs justify it.

### Derive OpenCode facts only from explicit integration-provided input

If `MAYI_OPENCODE_AGENT` is present and non-empty, `may-i` will add `:client/opencode` and `:opencode/agent = <value>` to the evaluation context. If the variable is absent, `may-i` will not synthesize any OpenCode facts.

This follows the existing conservative context model: missing runtime metadata means absent facts rather than guesses.

Alternatives considered:
- Add `:client/opencode` whenever `OPENCODE=1` is present: rejected because it would make direct or wrapper-free invocations behave differently based on ambient shell state.
- Populate additional facts such as `:opencode/mode` or session IDs now: rejected because the current integration only needs agent-aware policy today, and extra facts would expand surface area without a demonstrated use case.

### Ingest OpenCode context on the `eval` path and reuse existing evaluation plumbing

`may-i eval` will build a runtime fact set before calling the engine, similar in spirit to hook-mode ingestion, and will evaluate the command with context-aware evaluation. Human-readable output and JSON output will continue to include traces that reflect context-based matches and skips.

Alternatives considered:
- Special-case OpenCode entirely inside the engine: rejected because runtime ingestion belongs at the command boundary.
- Restrict OpenCode context to JSON mode only: rejected because human-readable `eval` should stay truthful to the same policy inputs.

### Keep the executed shell environment separate from the authorization contract

The initial change only requires the OpenCode integration to pass `MAYI_OPENCODE_AGENT` to the `may-i` evaluation subprocess. Propagating the same variable into the eventual executed shell command is out of scope.

This reduces environment leakage and keeps the contract focused on authorization rather than downstream tool behavior.

Alternatives considered:
- Export `MAYI_OPENCODE_AGENT` to every executed shell command: deferred because it is unnecessary for policy evaluation and broadens the observable environment of child processes.

## Risks / Trade-offs

- [OpenCode integration and `may-i` drift apart on variable naming] -> Document the contract clearly and cover it with integration-style tests.
- [Users want to simulate OpenCode agent context from the CLI] -> Keep the design open to a future CLI override without changing the fact model.
- [Future OpenCode context needs grow beyond the agent name] -> Use the existing namespaced fact model so additional facts can be added incrementally.
- [Trace output becomes harder to reason about] -> Reuse existing context trace annotations and add tests that assert OpenCode-gated rules remain inspectable.

## Migration Plan

- Update the current OpenCode integration to set `MAYI_OPENCODE_AGENT` when invoking `may-i`.
- Extend `may-i eval` runtime ingestion to read that variable and populate OpenCode context facts.
- Add tests and docs showing how rules can distinguish `plan` from `build`.
- Defer any CLI override until there is a concrete debugging or non-OpenCode integration need.

## Open Questions

- Should a future follow-up add `--opencode-agent` as an explicit testing/debugging override?
- Should later changes expose more OpenCode facts such as session IDs or agent classification (`primary` vs `subagent`)?

## 1. Explicit eval facts

- [x] 1.1 Add repeatable `may-i eval --fact` parsing for presence facts (`:client/opencode`) and scalar facts (`:opencode/agent=plan`), with validation errors for malformed entries.
- [x] 1.2 Remove `MAYI_OPENCODE_AGENT`-driven context synthesis from the direct `eval` path so OpenCode facts come only from explicit runtime facts.
- [x] 1.3 Add eval tests covering explicit OpenCode fact flags, missing facts, and the case where `MAYI_OPENCODE_AGENT` or `OPENCODE=1` is present but ignored.

## 2. Harness adapter refactor

- [x] 2.1 Introduce a shared hook evaluation flow plus harness adapter abstractions for payload matching, command/fact extraction, and response rendering.
- [x] 2.2 Move the existing Claude Code hook behavior onto the new adapter path without changing its decision semantics or response contract.
- [x] 2.3 Keep the adapter boundary extensible so future harnesses can be added without reworking the shared evaluation pipeline.

## 3. Hook routing behavior

- [x] 3.1 Update bare `may-i` hook mode to route Claude Code through the adapter flow and fail clearly for payloads that match no registered harness.
- [x] 3.2 Ensure hook routing remains a transport concern only and never introduces ambient integration state as policy facts.
- [x] 3.3 Add end-to-end hook tests covering Claude Code routing and unrecognized payload failures.

## 4. Docs and migration

- [x] 4.1 Update README and integration docs to replace `MAYI_OPENCODE_AGENT` guidance with explicit `--fact` examples for OpenCode.
- [x] 4.2 Document that OpenCode currently integrates through explicit `eval --fact` calls, while hook mode is organized around a future-friendly harness-adapter architecture.

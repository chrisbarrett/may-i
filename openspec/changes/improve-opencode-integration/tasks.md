## 1. Explicit eval facts

- [ ] 1.1 Add repeatable `may-i eval --fact` parsing for presence facts (`:client/opencode`) and scalar facts (`:opencode/agent=plan`), with validation errors for malformed entries.
- [ ] 1.2 Remove `MAYI_OPENCODE_AGENT`-driven context synthesis from the direct `eval` path so OpenCode facts come only from explicit runtime facts.
- [ ] 1.3 Add eval tests covering explicit OpenCode fact flags, missing facts, and the case where `MAYI_OPENCODE_AGENT` or `OPENCODE=1` is present but ignored.

## 2. Harness adapter refactor

- [ ] 2.1 Introduce a shared hook evaluation flow plus harness adapter abstractions for payload matching, command/fact extraction, and response rendering.
- [ ] 2.2 Move the existing Claude Code hook behavior onto the new adapter path without changing its decision semantics or response contract.
- [ ] 2.3 Add an OpenCode adapter that extracts the command and explicit runtime facts from the OpenCode payload and renders the OpenCode response envelope.

## 3. Hook routing behavior

- [ ] 3.1 Update bare `may-i` hook mode to detect Claude Code versus OpenCode from payload shape, using `OPENCODE=1` only as a routing hint when needed.
- [ ] 3.2 Ensure hook routing never turns `OPENCODE=1` into policy facts and that unknown payloads fail with a clear non-zero diagnostic.
- [ ] 3.3 Add end-to-end hook tests covering Claude Code routing, OpenCode routing, ambiguous routing with `OPENCODE=1`, and unrecognized payload failures.

## 4. Docs and migration

- [ ] 4.1 Update README and integration docs to replace `MAYI_OPENCODE_AGENT` guidance with explicit `--fact` examples for OpenCode.
- [ ] 4.2 Document bare hook-mode autodetection, including that `OPENCODE=1` is only a routing hint and never implicit policy input.

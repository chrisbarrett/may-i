## 1. Profile selection at hook entry

- [ ] 1.1 Rename `src/cmd_claude_code_hook.rs` to `src/cmd_hook.rs` and update the `mod` declaration in `src/main.rs:8` and the dispatch site at `src/main.rs:185`.
- [ ] 1.2 Introduce a private `HarnessProfile` enum in `src/cmd_hook.rs` with `ClaudeCode` and `Codex` variants and a constructor that takes the parsed stdin `serde_json::Value` and returns Codex iff the top-level object contains a `turn_id` key (presence-only, value not inspected); else ClaudeCode.
- [ ] 1.3 Add unit tests for the constructor covering: payload without `turn_id` → ClaudeCode; payload with `turn_id` set to a string → Codex; payload with `turn_id` set to `null` → Codex (presence semantics). Pure-function tests, no env mutation.

## 2. Per-profile context facts

- [ ] 2.1 Split `build_context` in `src/cmd_hook.rs` into a profile-aware function that takes `&HarnessProfile`. Claude Code branch keeps current behaviour (`:client/claude-code`, `:claude-code/*` keys).
- [ ] 2.2 Add the Codex branch: insert `:client/codex` presence and namespaced `:codex/permission-mode`, `:codex/cwd`, `:codex/tool-name`, `:codex/hook-event-name` scalars from the payload when present (mirroring the Claude Code branch).
- [ ] 2.3 Unit-test both branches with representative payloads; assert mutually exclusive client facts (`:client/codex` absent under Claude Code, `:client/claude-code` absent under Codex).

## 3. Codex response shape in renderers

- [ ] 3.1 Extend `render_hook` in `src/output/render.rs` to accept the harness profile and branch the JSON envelope: Claude Code keeps the existing shape; Codex emits the existing shape for `allow` / `deny` and the `additionalContext`-bearing shape for `ask` (omit `additionalContext` when reason is empty/absent).
- [ ] 3.2 Mirror the same profile parameter on `render_hook_trust_block` in `src/output/trust_block.rs` so a trust-block-driven `ask` under Codex uses the same `additionalContext` shape.
- [ ] 3.3 Thread the profile through `CommandPipeline::run_hook` in `src/pipeline.rs:226` (new method parameter), and update the two call sites that invoke the renderers (the trust-block path at 230 and the success path at 247).
- [ ] 3.4 Update the hook dispatch in `src/cmd_hook.rs` to pass the constructed `HarnessProfile` into `pipeline.run_hook`.
- [ ] 3.5 Add Rust unit tests in `src/output/render.rs` and `src/output/trust_block.rs` covering all six branches: {ClaudeCode, Codex} × {allow, ask-with-reason, deny}, plus Codex `ask` with no reason and Codex trust-block `ask`.

## 4. Integration tests

- [ ] 4.1 Add an integration test under `tests/` that drives `may-i` via `assert_cmd`, pipes a stdin payload containing `turn_id` plus an `ask`-triggering command, and asserts the Codex response shape (no `permissionDecision`, reason under `additionalContext`).
- [ ] 4.2 Add a companion test with the same payload but no `turn_id` and asserts the Claude Code response shape is unchanged.
- [ ] 4.3 Add an integration test for the Codex profile's `allow` and `deny` paths (payload with `turn_id`) that asserts the response shape matches Claude Code's bit-for-bit.

## 5. Verification

- [ ] 5.1 Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings`.
- [ ] 5.2 Run `cargo test` and `cargo tarpaulin`; inspect `lcov.info` for any uncovered branch in the new profile-dispatch and renderer code, and add targeted tests (preferring proptests where the input space is structured).
- [ ] 5.3 Run `openspec validate add-codex-hook-profile --strict`.
- [ ] 5.4 Manually verify with the three handoff fixtures by piping payloads of the form `{"tool_name": "Bash", "tool_input": {"command": "<cmd>"}, "turn_id": "t-1"}` into `may-i` (and the same payloads without `turn_id` for the Claude Code path) — confirm the Codex `ask` response no longer includes `permissionDecision` and that `allow`/`deny` are unchanged in both profiles.

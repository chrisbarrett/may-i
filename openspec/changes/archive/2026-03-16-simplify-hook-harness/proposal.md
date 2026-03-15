## Why

The hook harness abstraction (`HookRoute`, `Harness` enum, `route_hook()`) was designed to support multiple AI assistant integrations, but only Claude Code uses it and no other tools use hooks in the same way. This creates unnecessary indirection—three files (`cmd_hook.rs`, `hook_harness.rs`, `mod.rs` declaration) to handle what is essentially a single payload format. Simplifying to direct Claude Code handling reduces cognitive load and removes dead abstraction.

## What Changes

- **Remove** `src/hook_harness.rs` entirely
- **Rename** `src/cmd_hook.rs` to `src/cmd_claude_code_hook.rs`
- **Inline** Claude Code payload extraction and response formatting
- **Remove** generic `Harness` and `HookRoute` enums
- **Simplify** to directly handle the two cases: non-Bash tools (silent) and Bash commands (evaluate)
- No changes to behavior or output format

## Capabilities

### New Capabilities
<!-- No new capabilities -->

### Modified Capabilities
<!-- No spec-level changes -->

## Impact

- `src/hook_harness.rs` - **Deleted**
- `src/cmd_hook.rs` - **Renamed** to `src/cmd_claude_code_hook.rs`
- `src/main.rs` - Update module declaration and usage
- No API changes, no behavioral changes

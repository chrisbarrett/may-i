## Context

Current hook handling uses a generic abstraction layer:

```rust
// hook_harness.rs
pub enum HookRoute { Silent, Evaluate { ... harness: Harness } }
pub enum Harness { ClaudeCode }
pub fn route_hook(payload: &Value) -> Result<HookRoute>
```

This abstraction was designed for multiple harnesses but only Claude Code is supported. The `cmd_hook()` function matches on `HookRoute`, extracts fields, then uses the `Harness` enum to render responses. This creates three layers (payload → route → harness) for what is essentially:

1. Check if it's a Bash tool call
2. If not, do nothing
3. If yes, evaluate and return Claude Code format

## Goals / Non-Goals

**Goals:**
- Rename `cmd_hook.rs` to `cmd_claude_code_hook.rs` to reflect its specific purpose
- Inline Claude Code handling directly into the renamed file
- Remove `hook_harness.rs` module entirely
- Maintain identical behavior and output
- Reduce indirection and file count

**Non-Goals:**
- Add support for other AI assistants
- Change hook payload format
- Modify evaluation logic (just the routing/response layer)

## Decisions

### Decision: Rename file and inline everything

Rename `cmd_hook.rs` to `cmd_claude_code_hook.rs`, then move the logic from `hook_harness.rs` into it as private functions:

```rust
// cmd_claude_code_hook.rs
fn extract_command(payload: &Value) -> Option<String>  // None = silent
fn build_context(payload: &Value) -> ContextFacts
fn render_response(result: EvalResult) -> Value  // Claude Code format
```

**Rationale:** The file name should reflect that this is Claude Code-specific. All the logic is Claude Code-specific, so extracting it to named functions keeps the main function readable without creating a separate module that implies generality.

**Alternative considered:** Keep `hook_harness.rs` but remove the enums, just export functions. Rejected: still implies the abstraction might grow; better to make it clearly single-purpose.

### Decision: Preserve error behavior

Current code returns `Err` for:
- Missing `tool_input.command` (required field)
- Invalid JSON (handled in cmd_hook)

Silent success (return `Ok(())`) for:
- Non-Bash tool calls
- Missing `tool_name` field

This behavior will be preserved exactly.

### Decision: No tests for hook handling

There are currently no tests for hook handling. This change won't add them—testing would require mocking stdin and the config/engine dependencies. Out of scope for this simplification.

## Risks / Trade-offs

**Risk:** Future need for multiple harnesses  
**Mitigation:** If another AI assistant needs hook support, we can re-introduce abstraction then. The current abstraction doesn't actually help (it assumes all harnesses work the same way, which may not be true). YAGNI applies.

**Risk:** Code becomes less clear without the type system guidance of enums  
**Mitigation:** The logic is straightforward (if Bash, evaluate, else silent). Comments will document the Claude Code-specific assumptions.

**Risk:** Accidental behavior change  
**Mitigation:** Manual testing with actual Claude Code hook payloads to verify identical output.

## Migration Plan

No external migration. Internal changes only.

Steps:
1. Rename `cmd_hook.rs` to `cmd_claude_code_hook.rs`
2. Copy logic from `hook_harness.rs` into `cmd_claude_code_hook.rs` as private functions
3. Update `cmd_claude_code_hook()` to use inline logic
4. Update `main.rs` to use `mod cmd_claude_code_hook` and update command dispatch
5. Delete `hook_harness.rs`
6. Test with Claude Code hook payload

Rollback: Revert commit.

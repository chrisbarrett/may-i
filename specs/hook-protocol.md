# Hook Protocol

JSON interface between may-i and Claude Code. When stdin is a pipe, may-i
reads a hook payload, evaluates the command, and writes a response.

---

## R12: Payload parsing

**Given** a JSON payload on stdin with shape:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "<shell command>"
  }
}
```

**When** `tool_name` is `"Bash"` **Then** evaluate `tool_input.command` against
config and return a decision.

**When** `tool_name` is anything other than `"Bash"` **Then** exit silently with
code 0 (implicit allow). Non-Bash tools are outside scope.

**Verify:** `cargo test -- hook`

## R13: Response format

**Given** evaluation produces a decision **Then** write to stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "optional reason"
  }
}
```

`permissionDecision` is one of `"allow"`, `"ask"`, `"deny"` (lowercase
strings). `permissionDecisionReason` is present only when the matching rule
provides a reason string.

**Verify:** `cargo test -- hook`; snapshot tests for all three decisions

## R14: Input guard

**Given** stdin exceeds 64KB **Then** read only the first 65536 bytes.

This prevents a malicious or buggy caller from causing unbounded memory
allocation. Truncated input will fail JSON parsing and produce an error exit.

**Verify:** integration test with oversized payload

## R15: Error behavior

**Given** stdin contains invalid JSON or missing fields **Then** exit with a
non-zero code and a diagnostic on stderr.

The hook must never silently swallow errors — Claude Code interprets non-zero
exit as "ask the user."

**Verify:** `cargo test -- hook`; assert exit code on malformed input

## Constraints

- Hook mode latency: <50ms p99 (Claude Code blocks on response)
- JSON format must match Claude Code hook protocol exactly
- No output on stdout for non-Bash tools (silent pass-through)

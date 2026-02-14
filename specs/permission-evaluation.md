# may-i — Shell Command Authorization Evaluator

Rust CLI that evaluates shell commands against user-configurable authorization
rules, returning `allow`/`deny`/`ask` decisions. Primary consumer is Claude Code
(pre-tool-use hook). Also exposes `eval` and `check` subcommands for standalone
use.

Config lives at `~/.config/may-i/config.toml`. Built-in defaults are compiled
into the binary; user rules prepend to (and override) defaults.

### Related specs

- [Shell Parser](shell-parser.md) — R5, R6
- [Configuration](configuration.md) — R10, R10a, R10b, R10c
- [Security Filters](security-filters.md) — R11

---

## Feature: CLI Interface

### R1: Hook mode (default)

**Given** bare `may-i` invocation **When** stdin contains a Claude Code hook
payload **Then** extract `tool_input.command`, evaluate, write hook response to
stdout

Stdin:

```json
{
  "type": "Bash",
  "tool_input": { "command": "git push origin main" }
}
```

Stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Dangerous git operation"
  }
}
```

If `type` is not `"Bash"`, exit 0 with no output.

**Verify:** integration tests with fixture payloads; `cargo test`

### R2: Eval subcommand

```
$ may-i eval 'cat foo.txt'
allow: Read-only filesystem access

$ may-i eval --json 'cat foo.txt'
{"decision":"allow","reason":"Read-only filesystem access"}
```

**Verify:** `cargo test -- eval`

### R3: Check subcommand

`may-i check` loads config, validates syntax/semantics, runs all embedded
examples against the rule set, reports pass/fail per example.

**Verify:** `cargo test -- check`

### R4: Exit codes

| Scenario          | Code |
| :---------------- | :--- |
| Success           | 0    |
| Config/rule error | 1    |
| Example failure   | 1    |

**Verify:** integration tests assert exit codes

---

## Feature: Rule Engine

### R7: Evaluation pipeline

Evaluation order:

1. Security filters (R11) — deny on credential file access
2. AST decomposition — extract all simple commands from compound structures
3. Per-command: check wrappers (R9), then deny rules, then first-match
4. Aggregate: most restrictive decision wins (`deny` > `ask` > `allow`)
5. No match → `ask`

```
"git status && mkfs /dev/sda"  →  deny (mkfs wins over git status)
"cat foo | grep bar"           →  allow (both allowed)
"nohup curl -I example.com"   →  allow (unwrap nohup, curl HEAD)
```

**Verify:** `cargo test -- engine`

### R8: Flag expansion

`-abc` expands to `-a -b -c` before rule matching.

**Verify:** `cargo test -- tokenizer`

### R9: Wrapper unwrapping

Wrappers are recognized and their inner command extracted for evaluation.
Recursion depth capped at 5.

Built-in wrappers: `nohup`, `env`, `nice`, `time`, `strace` (after-flags);
`mise exec --`, `terragrunt exec --` (after delimiter);
`nix shell/develop --command`, `nix-shell --run` (after keyword).

User-configurable via `[[wrappers]]` in config (see R10).

**Verify:** `cargo test -- engine::wrapper`

---

## Constraints

- **Latency:** <50ms p99 in hook mode (Claude Code blocks on responses)
- **Input size:** handle up to 64KB without degradation
- **Safety:** no panics on any input; all public APIs return `Result`/`Option`;
  no `unsafe` in parser or evaluator; fuzz testing required
- **Compat:** TOML config; hook JSON matches Claude Code protocol exactly;
  statically linkable binary

---

## Tasks

- [ ] [R5,R6] Shell parser with full grammar, quoting, redirections, fuzz tests
- [ ] [R7,R8,R9] Rule engine: priority pipeline, compound eval, wrappers, flag
      expansion
- [ ] [R11] Security filters with deep AST path extraction
- [ ] [R10,R10a,R10b] Config loader: TOML parsing, matchers, example validation
- [ ] [R10c] Port built-in defaults from reference implementation
- [ ] [R1] Hook mode (stdin JSON → eval → stdout JSON)
- [ ] [R2] Eval subcommand
- [ ] [R3] Check subcommand

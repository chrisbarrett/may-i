# may-i — Shell Command Authorization Evaluator

Rust CLI that evaluates shell commands against user-configurable authorization
rules, returning `allow`/`deny`/`ask` decisions. Primary consumer is Claude Code
(pre-tool-use hook). Also exposes `eval` and `check` subcommands for standalone
use.

Config lives at `~/.config/may-i/config.lisp`. Built-in defaults are compiled
into the binary; user rules prepend to (and override) defaults.

### Related specs

- [CLI Interface](cli-interface.md) — R1–R5
- [Shell Parser](shell-parser.md) — R5–R7
- [Configuration](configuration.md) — R10–R10f
- [Hook Protocol](hook-protocol.md) — R12–R15
- [Variable Resolution](variable-resolution.md) — R16–R21
- [Visitor Pipeline](visitor-pipeline.md) — R22–R29
- [Evaluation Trace](evaluation-trace.md) — R30–R35
- [Domain Model](domain-model.md) — R36–R43
- [Security Filters](security-filters.md) — R11 (removed)

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

Built-in wrappers: `nohup`, `env`, `nice`, `time`, `strace` (`:command+args`);
`mise exec --`, `terragrunt exec --` (`(positional ...) (flag "--" ...)`);
`nix shell/develop --command` (`(positional ...) (flag "--command" ...)`);
`ssh` (`(positional * :command+args)`).

User-configurable via `(wrapper ...)` in config (see R10).

**Verify:** `cargo test -- engine::wrapper`

---

## Constraints

- **Latency:** <50ms p99 in hook mode (Claude Code blocks on responses)
- **Input size:** handle up to 64KB without degradation
- **Safety:** no panics on any input; all public APIs return `Result`/`Option`;
  no `unsafe` in parser or evaluator; fuzz testing required
- **Compat:** S-expression config; hook JSON matches Claude Code protocol
  exactly; statically linkable binary

---

## Tasks

- [ ] [R5,R6] Shell parser with full grammar, quoting, redirections, fuzz tests
- [ ] [R7,R8,R9] Rule engine: priority pipeline, compound eval, wrappers, flag
      expansion
- [ ] [R11] Security filters with deep AST path extraction
- [ ] [R10,R10a–R10f] Config loader: s-expression parsing, matchers, example
      validation
- [ ] [R10e] Port built-in defaults from reference implementation
- [ ] [R1] Hook mode (stdin JSON → eval → stdout JSON)
- [ ] [R2] Eval subcommand
- [ ] [R3] Check subcommand

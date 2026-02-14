# may-i

A Rust CLI that evaluates shell commands against user-configurable authorization
rules, returning `allow`, `deny`, or `ask` decisions. Designed as a pre-tool-use
hook for Claude Code to control which Bash commands require user confirmation.

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/may-i`.

## Usage

### Hook Mode (Default)

Reads a Claude Code hook JSON payload from stdin, extracts the command, evaluates
it, and writes a hook response to stdout. Non-Bash tool types are silently passed
through.

```bash
echo '{"type":"Bash","tool_input":{"command":"ls -la"}}' | may-i
# Output: {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Read-only filesystem inspection"}}
```

### Direct Evaluation

Evaluate a command directly and print the result.

```bash
may-i eval 'cat README.md'
# Output: allow: Read-only file operations

may-i eval 'rm -rf /'
# Output: deny: Recursive deletion from root is dangerous

may-i eval --json 'git push'
# Output: {"decision":"ask","reason":"No matching rule"}
```

### Config Validation

Validate the config file and run all embedded examples.

```bash
may-i check
# Output:
#   PASS: curl -I https://example.com → allow
#   PASS: curl --head https://example.com → allow
#
# 2 passed, 0 failed
```

## Claude Code Integration

Add to `.claude/settings.json` in your project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["may-i"]
      }
    ]
  }
}
```

Now Claude Code will consult may-i before executing Bash commands. Commands that
return `allow` run immediately, `deny` blocks execution, and `ask` prompts the
user.

## Configuration

Config location (in priority order):

1. `$MAYI_CONFIG`
2. `$XDG_CONFIG_HOME/may-i/config.toml`
3. `~/.config/may-i/config.toml`

A starter config is created automatically on first run. The config has three
sections:

### Rules

Rules match commands by exact name, list of names, or regex. Each rule specifies
a decision (`allow`, `deny`, or `ask`) and optional matchers for arguments.

```toml
[[rules]]
command = "rm"
decision = "deny"
reason = "Recursive deletion from root is dangerous"
[rules.args]
anywhere = ["-r", "--recursive"]
anywhere_also = ["/"]

[[rules]]
command = ["cat", "head", "tail"]
decision = "allow"
reason = "Read-only file operations"
```

Available argument matchers:

- `positional` — Match arguments at specific positions
- `anywhere` — Match if any of these tokens appear anywhere
- `anywhere_also` — Additional required tokens (logical AND with `anywhere`)
- `forbidden` — Deny if any of these flags are present

**Deny rules always win** regardless of position. For other rules, first match
wins. Commands with no matching rule default to `ask`.

### Examples

Rules can embed examples for validation via `may-i check`.

```toml
[[rules]]
command = "curl"
decision = "allow"
reason = "HTTP client (read-only operations)"
[rules.args]
forbidden = ["-d", "--data", "-F", "--form"]

  [[rules.examples]]
  command = "curl -I https://example.com"
  expected = "allow"

  [[rules.examples]]
  command = "curl --head https://example.com"
  expected = "allow"

  [[rules.examples]]
  command = "curl -d 'data' https://example.com"
  expected = "deny"
```

### Wrappers

Wrappers recognize commands that wrap other commands and extract the inner
command for evaluation. Recursion is capped at depth 5.

```toml
[[wrappers]]
command = "nohup"
inner_command = "after_flags"

[[wrappers]]
command = "mise"
inner_command = { after = "--" }
[wrappers.args]
positional = ["exec"]
```

### Security

Regex patterns for blocked credential paths. User config can only add to these
defaults, never replace them.

```toml
[security]
blocked_paths = [
  '(^|/)\\.env($|[./])',
  '(^|/)\\.ssh/',
  '(^|/)\\.aws/',
  # ... more patterns
]
```

## How Evaluation Works

1. **Security filters** — Deny on credential/sensitive file access (`.env`,
   `.ssh/`, `.aws/`, etc.)
2. **Dynamic shell detection** — Command substitution, parameter expansion, etc.
   escalate to `ask` (can't be statically analyzed)
3. **AST decomposition** — Extract all simple commands from compound structures
   (pipelines, `&&`/`||`, subshells, etc.)
4. **Per-command evaluation** — Check wrappers, then deny rules, then
   first-match
5. **Aggregate decision** — Most restrictive wins (`deny` > `ask` > `allow`)
6. **Default fallback** — No matching rule defaults to `ask`

## Starter Config Defaults

**Denied operations:**

- `rm` with `-r`/`--recursive` and `/`
- Filesystem tools: `mkfs`, `dd`, `fdisk`, `parted`, `gdisk`
- System control: `shutdown`, `reboot`, `halt`, `poweroff`, `init`
- Firewall: `iptables`, `nft`, `pfctl`

**Allowed operations:**

- File reading: `cat`, `head`, `tail`, `less`, `more`, `wc`, `sort`, `uniq`
- Filesystem inspection: `ls`, `tree`, `file`, `stat`, `du`, `df`
- Text search: `grep`, `rg`, `ag`, `ack`
- File lookup: `locate`, `which`, `whereis`, `type`
- Shell builtins: `echo`, `printf`, `true`, `false`, `test`, `[`
- System info: `date`, `hostname`, `uname`, `whoami`, `id`, `printenv`, `env`
- Monitoring: `ps`, `top`, `uptime`, `free`, `vmstat`, `iostat`
- Path utilities: `basename`, `dirname`, `realpath`, `readlink`, `pwd`

Commands removed from allow list for safety:

- `tee` — writes files
- `sed`, `awk` — can modify files in-place

## Technical Details

- **Shell parser** — Recursive descent parser producing typed AST supporting
  pipelines, compound commands, redirections, quoting, parameter expansion,
  command substitution, process substitution, brace expansion, globs, heredocs,
  etc.
- **Flag expansion** — `-abc` is expanded to `-a -b -c` before matching
- **Security anchoring** — `blocked_path` patterns are anchored as path
  components to avoid false positives
- **Performance** — Designed for <50ms p99 latency in hook mode
- **Input limits** — Handles up to 64KB stdin input
- **Reliability** — No panics on any input

## Project Structure

```
src/
  main.rs         — entry point
  cli.rs          — CLI interface (hook mode, eval, check)
  config.rs       — TOML config loading and parsing
  engine.rs       — rule evaluation engine
  parser.rs       — recursive descent shell parser
  security.rs     — security filters (blocked paths, dynamic parts)
  types.rs        — shared domain types
specs/            — specification documents
```

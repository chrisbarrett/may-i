# may-i

A tool allowing you to declare rich, realiable Bash tool authorization rules in
Claude Code, improving safety while nagging you less with permission prompts.
It's a nice middle-ground between "nag me for everything" and "dangerously wipe
my boot partition". ᕕ( ᐛ )ᕗ

`may-i` is configured using a TOML file at `~/.config/may-i/config.toml`. Edits
to this file take effect immediately--no need to re-launch Claude Code to pick
up changes. 😇

Permissions checks use a fully-featured Bash parser, making your rules much more
accurate than naive globbing. It can handle all the conditionals, complex
redirections, and other shell features that your agents might use.

## Installation

Build this program and add it to your PATH:

1. you can do it with Cargo, or
2. use the flake as an input; the derivation to use will be at
   `packages.default.${system}`.

Then, tell Claude Code to use `may-i` as a bash tool pre-authorizer in your
`.claude/settings.json`:

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

`may-i` will create a starter config for you at
`~/.config/may-i/config.toml`--customise it to your heart's content.

## Direct Evaluation

You can use `may-i eval "${command}"` to test out the authorier.

```bash
may-i eval 'cat README.md'
# Output: allow: Read-only file operations

may-i eval 'rm -rf /'
# Output: deny: Recursive deletion from root is dangerous

may-i eval --json 'git push'
# Output: {"decision":"ask","reason":"No matching rule"}
```

## Validation & Testing

Use `may-i check` to test whether your config is valid. Any inline
examples+expectations you wrote will also be checked.

```bash
may-i check
# Output:
#   PASS: curl -I https://example.com → allow
#   PASS: curl --head https://example.com → allow
#
# 2 passed, 0 failed
```

## Configuration

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

You can teach `may-i` to treat certain commands as _wrappers_; this is
particularly useful for commands like `time`, `mise`, etc. Validation is
performed against the inner command.

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

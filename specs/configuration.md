# Configuration

TOML-based configuration for authorization rules, wrapper definitions, and
security settings. Built-in defaults are compiled into the binary; user rules
prepend to (and override) defaults.

---

## R10: Config file location

1. `$MAYI_CONFIG`
2. `$XDG_CONFIG_HOME/may-i/config.toml`
3. `~/.config/may-i/config.toml`

No config file → built-in defaults only.

**Verify:** `cargo test -- config::location`

## R10a: Config schema

```toml
# Rules evaluated in order. Deny rules always win regardless of position.
# User rules prepend to built-in defaults.

[[rules]]
command = "rm"                          # string, regex, or array of strings
args.anywhere = ["-r", "--recursive"]   # any token matches
args.anywhere_also = ["/"]              # AND with above
decision = "deny"
reason = "Recursive deletion from root"

[[rules]]
command = ["cat", "ls", "grep"]
decision = "allow"

[[rules]]
command = "curl"
args.forbidden = ["-d", "--data", "-F", "--form", "-X", "--request"]
decision = "allow"
reason = "GET request (no mutating flags)"

[[rules]]
command = "aws"
args.positional = ["*", "^(get|describe|list).*"]
decision = "allow"

[[rules]]
command = "curl"
args.anywhere = ["-I", "--head"]
decision = "allow"
reason = "HEAD request is read-only"

  [[rules.examples]]
  command = "curl -I https://example.com"
  expected = "allow"

  [[rules.examples]]
  command = "curl --head https://example.com"
  expected = "allow"

[[wrappers]]
command = "nohup"
inner_command = "after_flags"

[[wrappers]]
command = "mise"
args.positional = ["exec"]
inner_command = { after = "--" }

[[wrappers]]
command = "nix"
args.positional = ["shell"]
inner_command = { after = "--command" }

[security]
blocked_paths = [
  '\.env',
  '\.ssh/',
  '\.aws/',
  '\.gnupg/',
  '\.docker/',
  '\.kube/',
  'credentials\.json',
  '\.netrc',
  '\.npmrc',
  '\.pypirc',
]
```

**Verify:** `cargo test -- config::parse`; `may-i check`

## R10b: Arg matcher semantics

| Matcher      | Semantics                                        |
| :----------- | :----------------------------------------------- |
| `positional` | Match positional args (skip flags). `"*"` = any. |
| `anywhere`   | Token appears anywhere in argv                   |
| `forbidden`  | Rule matches if pattern is NOT found             |

Multiple matchers on one rule are AND-ed. Values: `"literal"` (exact),
`"^regex"` (starts with `^` → regex), `["a", "b"]` (enum), `"*"` (wildcard).

**Verify:** `cargo test -- config::matchers`

## R10c: Built-in defaults

The binary ships with defaults matching the [reference implementation][ref]:

- **Deny:** `mkfs`, `dd`, `fdisk`, `shutdown`, `reboot`, `iptables`, dangerous
  `gh` ops (repo delete, release create, secret set, ssh-key add)
- **Allow:** read-only fs, system state, shell utils, safe git/build/archive
  tools, documentation access
- **Ask:** network ops with data, destructive git, package installs, docker
  exec, terraform apply, service control

[ref]: /Users/chris/src/chrisbarrett/claude-plugins/plugins/core-hooks/hooks/pre-tool-use/bash-authorizer/rules.ts

**Verify:** `cargo test -- defaults`; `may-i check` exercises built-in examples

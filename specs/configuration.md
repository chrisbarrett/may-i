# Configuration

S-expression DSL for authorization rules, wrapper definitions, and security
settings. Built-in defaults are compiled into the binary; user rules prepend to
(and override) defaults.

---

## R10: Config file location

1. `$MAYI_CONFIG`
2. `$XDG_CONFIG_HOME/may-i/config.lisp`
3. `~/.config/may-i/config.lisp`

No config file → built-in defaults only.

**Verify:** `cargo test -- config::location`

## R10a: S-expression grammar

```
file      = form*
form      = rule | wrapper | security

rule      = "(" "rule" command args? decision example* ")"
command   = "(" "command" cmd-val ")"
cmd-val   = STRING | "(" "or" STRING+ ")" | "(" "regex" STRING ")"
args      = "(" "args" matcher ")"
matcher   = pos | exact | any | forb | and | or | not
pos       = "(" "positional" pat+ ")"
exact     = "(" "exact" pat+ ")"
any       = "(" "anywhere" pat+ ")"
forb      = "(" "forbidden" pat+ ")"
and       = "(" "and" matcher matcher+ ")"
or        = "(" "or" matcher matcher+ ")"
not       = "(" "not" matcher ")"
pat       = STRING | "*" | "(" "regex" STRING ")" | "(" "or" STRING+ ")"
decision  = "(" "allow" reason? ")" | "(" "deny" reason? ")" | "(" "ask" reason? ")"
reason    = STRING

example   = "(" "example" STRING decision-kw ")"
decision-kw = "allow" | "deny" | "ask"

wrapper   = "(" "wrapper" STRING kind ")"
          | "(" "wrapper" STRING "(" "positional" pat+ ")" kind ")"
kind      = "after-flags" | "(" "after" STRING ")"

security  = "(" "blocked-paths" STRING+ ")"

STRING    = quoted string (double-quote, backslash escapes)
```

Comments: `;` to end of line.

## R10b: Config example

```scheme
;; Rules evaluated in order. Deny rules always win regardless of position.
;; User rules prepend to built-in defaults.

;; Deny: recursive deletion from root
(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (deny "Recursive deletion from root"))

;; Allow: simple read-only commands
(rule (command (or "cat" "ls" "grep"))
      (allow))

;; Allow: curl without mutating flags (defaults to GET)
(rule (command "curl")
      (args (forbidden "-d" "--data" "-F" "--form" "-X" "--request"))
      (allow "GET request (no mutating flags)"))

;; Allow: aws read-only operations
(rule (command "aws")
      (args (positional * (regex "^(get|describe|list).*")))
      (allow))

;; Allow: curl HEAD requests
(rule (command "curl")
      (args (anywhere "-I" "--head"))
      (allow "HEAD request is read-only")
      (example "curl -I https://example.com" allow)
      (example "curl --head https://example.com" allow))

;; Deny: dangerous gh operations (unions of positional patterns)
(rule (command "gh")
      (args (or (positional "repo" (or "create" "delete" "fork"))
                (positional "release" (or "create" "delete" "upload"))
                (positional "secret" (or "set" "delete"))
                (positional "ssh-key" (or "add" "delete"))))
      (deny "Supply chain attack vector"))

;; Allow: read-only gh api (GET, no fields)
(rule (command "gh")
      (args (and (positional "api")
                 (forbidden "-X" "--method" "-f" "--field" "-F" "--raw-field")))
      (allow "Read-only API call"))

;; Wrappers
(wrapper "nohup" after-flags)
(wrapper "mise" (positional "exec") (after "--"))
(wrapper "nix" (positional "shell") (after "--command"))

;; Security: blocked path patterns (regexes, appended to built-in defaults)
(blocked-paths
  "\\.env"
  "\\.ssh/"
  "\\.aws/")
```

**Verify:** `cargo test -- config::parse`; `may-i check`

## R10c: Matcher semantics

| Form           | Semantics                                            |
| :------------- | :--------------------------------------------------- |
| `positional`   | Match positional args (skip flags). `*` = any value. |
| `exact`        | Like `positional`, but requires exact arg count match |
| `anywhere`     | Token appears anywhere in argv (OR over values)      |
| `forbidden`    | Sugar for `(not (anywhere ...))` — none found        |
| `and`          | All sub-matchers must match                          |
| `or`           | Any sub-matcher must match                           |
| `not`          | Inverts a sub-matcher                                |

Pattern values: `"literal"` (exact match), `(regex "^pat")` (regex match),
`(or "a" "b")` (any of), `*` (wildcard, unquoted).

**Verify:** `cargo test -- config::matchers`

## R10d: Examples in rules

Rules may contain inline `(example ...)` forms for self-testing:

```scheme
(rule (command "curl")
      (args (anywhere "-I" "--head"))
      (allow "HEAD request")
      (example "curl -I https://example.com" allow)
      (example "curl --head https://example.com" allow))
```

`may-i check` evaluates all examples (built-in and user) and reports failures.

**Verify:** `may-i check`

## R10e: Built-in defaults

The binary ships with defaults matching the [reference implementation][ref]:

- **Deny:** `mkfs`, `dd`, `fdisk`, `shutdown`, `reboot`, `iptables`, dangerous
  `gh` ops (repo delete, release create, secret set, ssh-key add)
- **Allow:** read-only fs, system state, shell utils, safe git/build/archive
  tools, documentation access
- **Ask:** network ops with data, destructive git, package installs, docker
  exec, terraform apply, service control

[ref]: /Users/chris/src/chrisbarrett/claude-plugins/plugins/core-hooks/hooks/pre-tool-use/bash-authorizer/rules.ts

**Verify:** `cargo test -- defaults`; `may-i check` exercises built-in examples

## R10f: S-expression parser

The parser is a standalone module (`config::sexpr`) with no external
dependencies. It produces a simple AST:

```
Atom(String) | List(Vec<Sexpr>)
```

Quoted strings support `\\`, `\"`, `\n`, `\t` escapes. Unquoted atoms are bare
words (letters, digits, `-`, `_`, `*`, `.`, `/`, `^`). Parentheses delimit
lists. `;` comments extend to end of line.

**Verify:** `cargo test -- config::sexpr`

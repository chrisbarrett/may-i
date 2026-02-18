# may-i

A tool allowing you to declare rich, reliable Bash tool authorization rules in
Claude Code, improving safety while nagging you less with permission prompts.
It's a nice middle-ground between "nag me for everything" and "dangerously wipe
my boot partition".

`may-i` is configured using an s-expression file at
`~/.config/may-i/config.lisp`. Edits to this file take effect immediately--no
need to re-launch Claude Code to pick up changes.

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
`~/.config/may-i/config.lisp`--customise it to your heart's content.

## Direct Evaluation

You can use `may-i eval "${command}"` to test out the authorizer.

```bash
may-i eval 'cat README.md'
# Output: allow: Read-only file operations

may-i eval 'rm -rf /'
# Output: deny: Recursive deletion from root

may-i eval --json 'git push'
# Output: {"decision":"ask","reason":"No matching rule for command `git`"}
```

## Validation & Testing

Use `may-i check` to test whether your config is valid. Any inline
checks you wrote will also be validated.

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
Matchers can be composed with `and`, `or`, and `not`.

```scheme
;; Deny recursive deletion from root
(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (deny "Recursive deletion from root"))

;; Allow simple read-only commands
(rule (command (oneof "cat" "head" "tail"))
      (allow "Read-only file operations"))

;; Allow curl without mutating flags
(rule (command "curl")
      (args (forbidden "-d" "--data" "-F" "--form" "-X" "--request"))
      (allow "GET request (no mutating flags)"))

;; Deny dangerous gh operations
(rule (command "gh")
      (args (or (positional "repo" (oneof "create" "delete" "fork"))
                (positional "secret" (oneof "set" "delete"))))
      (deny "Supply chain attack vector"))
```

Available argument matchers:

- `positional` — Match arguments at specific positions (skip flags); `*` = any
- `anywhere` — Match if any of these tokens appear anywhere (OR semantics)
- `forbidden` — Rule matches only if none of these flags are present
- `and` — All sub-matchers must match
- `or` — Any sub-matcher must match
- `not` — Inverts a sub-matcher

Pattern values: `"literal"` (exact match), `(regex "^pat")` (regex match),
`(oneof "a" "b")` (any of), `*` (wildcard, unquoted).

**Deny rules always win** regardless of position. For other rules, first match
wins. Commands with no matching rule default to `ask`.

### Cond branching

Use `cond` inside `(args ...)` to express multiple branches within a single
rule. This is useful when you want to allow specific args but deny everything
else for the same command -- something separate rules can't do because deny
always wins across rules.

```scheme
(rule (command "tmux")
      (args (cond
              ((positional "source-file" (or "~/.tmux.conf"
                                             "~/.config/tmux/tmux.conf"))
               (effect :allow "Reloading config is safe"))
              (else
               (effect :deny "Unknown tmux command"))))
      (check :allow "tmux source-file ~/.tmux.conf"
             :deny "tmux kill-server"))
```

Each branch is `(matcher effect)` where the matcher is a regular arg matcher
(e.g. `(positional ...)`, `(anywhere ...)`) or a wildcard (`else`). Branches
are tried in order; first match wins. If no branch matches, the rule is skipped.

When `cond` is the top-level matcher, effects come from branches and the rule
must not have a separate `(effect ...)`. When nested inside combinators
(`and`/`or`/`not`), it acts as a boolean matcher and the rule's own effect
applies.

### Inline Checks

Rules can embed checks for validation via `may-i check`.

```scheme
(rule (command "curl")
      (args (anywhere "-I" "--head"))
      (effect :allow "HEAD request is read-only")
      (check :allow "curl -I https://example.com"
             :allow "curl --head https://example.com"))
```

### Wrappers

You can teach `may-i` to treat certain commands as _wrappers_; this is
particularly useful for commands like `time`, `mise`, etc. Validation is
performed against the inner command.

```scheme
(wrapper "nohup" after-flags)
(wrapper "mise" (positional "exec") (after "--"))
(wrapper "nix" (positional "shell") (after "--command"))
```

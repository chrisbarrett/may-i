# may-i

`may-i` is a permissions check system for agents that can call shell commands
via tools. You write expressive rules describing what's safe for your agents to
run without prompting you, and block them from executing the really bad stuff.

The goal is giving you the convenience of `--dangerously-skip-permissions`, but
with way more safety.

Here you can see `may-i` in action: we have a config that defines prod servers
as 'immutable', and a dodgy command that breaks the rules is blocked.

![may-i trace showing ssh plus sudo unwrapping and a denied prod mutation](docs/assets/ssh-sudo-prod-deny.png)

<details>
<summary>Policy used for this demo</summary>

This policy teaches `may-i` that `sudo` and `ssh` interpret their arguments as
commands. `rm` is denied on immutable hosts, even when snuck in via `sudo`.

```scheme
; Define a reusable predicate for immutable production hosts
(define immutable
  (and (fact? :via/ssh)
       (fact? [:ssh/host (regex "(^|@).*prod.*")])))

; Allow echo always
(rule "echo" :effect [:allow "Local echo is always fine"])

; Deny rm on immutable hosts using the defined predicate
(rule "rm"
  (when immutable (effect :deny "Production hosts are immutable"))
  :effect (effect :allow))

; SSH unwraps to evaluate the inner command
(rule "ssh"
  (positional [:ssh/host *] . (may-i *))
  :effect (effect :deny))

; Sudo unwraps to evaluate the inner command
(rule "sudo"
  (positional . (may-i *))
  :effect (effect :deny))
```

</details>

## Why use it?

Without `may-i`, agent permission systems tend to be noisy. Safe, routine
commands still trigger prompts, which interrupts the flow and trains you to
click through approvals.

`may-i` lets you describe your own policy for what an agent may do
automatically, what should still ask, and what should be blocked outright.

## How it works

When an agent wants to run a shell command, `may-i` evaluates that command
against your policy and returns one of three decisions:

- `allow` - run it without asking
- `ask` - escalate to the harness's normal permission prompt
- `deny` - block it

`may-i` parses shell accurately before applying rules, so policy decisions are
based on the real command structure rather than brittle string matching.

## Core concepts

### Rules

Rules match commands and decide what should happen. This is the core of the
system: "allow these", "ask for those", "never permit these".

Rules match commands using pattern effects. Use `:effect` to specify the default:

```scheme
; Simple rule: allow cat
(rule "cat" :effect :allow)

; Rule with pattern matching: ask for rm -rf
(rule "rm"
  (when (anywhere "-rf" "--recursive")
    (effect :ask "Recursive deletion requires confirmation"))
  :effect (effect :allow))
```

### Pattern Effects

Pattern effects match command arguments and return `Allow` on success, `Nil` otherwise. They can be used in `when`, `unless`, `if`, and `cond` to make decisions conditional:

```scheme
; Match positional arguments (skipping flags)
(positional "git" "push")
(positional [:host *] "deploy")

; Match anywhere in args
(anywhere "--force" "-f")

; Require exact argument match
(exact "ls" "-la")

; Combined with conditionals
(when (and (fact? :via/ssh) (positional "rm" "-rf"))
  (effect :deny))

(if (anywhere "--force")
  (effect :ask "Force flag detected")
  (effect :allow))
```

### Effects

Effects are evaluated in order within a rule until one returns a decision:

```scheme
; Terminal effects
(effect :allow)
(effect :ask "Reason for asking")
(effect :deny "Why this is blocked")

; Recursive evaluation
(may-i PATTERN)                    ; Evaluate inner command

; Combinators
(and EFFECT ...)                   ; All must succeed
(or EFFECT ...)                    ; First to succeed wins
(not EFFECT)                       ; Invert Allow/Nil

; Conditionals
(cond ((PATTERN) EFFECT) ... (else EFFECT))  ; Pattern-based branching
(when PATTERN EFFECT)              ; Conditional effect
(unless PATTERN EFFECT)            ; Negated conditional
(if PATTERN THEN ELSE)             ; If-then-else
```

Effects evaluate to `Decision | Nil`. The `:effect` keyword specifies the default if all effects return `Nil`. Decisions combine with "most restrictive wins": `Deny > Ask > Allow`.

### Named Predicates

Define reusable predicates with `(define ...)`:

```scheme
(define prod-host
  (and (fact? :via/ssh)
       (fact? [:ssh/host (regex "^prod-")])))

(define dangerous-rm
  (and (positional "rm")
       (anywhere "-r" "--recursive")))

; Use the defined predicates
(rule "rm"
  (when (and prod-host dangerous-rm)
    (effect :deny "Recursive delete on production hosts"))
  :effect (effect :allow))
```

### Recursive Evaluation

The `(may-i ...)` effect enables unwrapping commands like `ssh`, `sudo`, `nix`,
and `mise` to evaluate the inner command:

```scheme
; SSH unwrap: capture host as fact, evaluate inner command
(rule "ssh"
  (positional [:ssh/host *] . (may-i *))
  :effect (effect :deny "No SSH commands allowed by default"))

; Sudo unwrap: evaluate inner command directly
(rule "sudo"
  (positional . (may-i *))
  :effect (effect :deny))

; Mise exec unwrap: skip "exec", evaluate rest
(rule "mise"
  (positional "exec" . (may-i *))
  :effect (effect :deny))
```

The dot (`.`) syntax explicitly marks where remaining arguments become the
recursive evaluation target. If `(may-i *)` doesn't match, the rule falls through
to the `:effect` default.

### Checks

Checks are inline tests for your policy. They help keep your config predictable
as it grows:

```scheme
(rule "mv"
  (if (anywhere "-f" "--force")
      (effect :ask "Force moves can be destructive")
      (effect :allow))
  :effect (effect :deny)
  (check :allow "mv foo bar"
         :ask "mv -f foo bar"))
```

Run `may-i check` to verify all checks pass.

## A small example

For example, you might want to allow `mv` by default, but still require approval
when it uses `--force`:

```scheme
(rule "mv"
  (if (anywhere "-f" "--force")
      (effect :ask "File moves with -f/--force can be destructive")
      (effect :allow))
  :effect (effect :deny)
  (check :allow "mv foo bar"
         :ask "mv -f foo bar"))
```

Stack enough rules like this together and the agent can get much more done
without bothering you for routine work.

## Context-aware decisions

The most useful policies usually depend on context, not just command names.

For example, you might allow `journalctl` only when it is reached through `ssh`
to a production host, or allow routine `git` commands for an implementation
agent while requiring approval for the same commands in a planning agent.

That is what facts are for. Facts are bits of runtime context attached to
command evaluation. Some facts come from runtime integrations; others come from
recursive evaluation while `may-i` unwraps a command.

```scheme
; Block kubectl in production environment
(rule "kubectl"
  (when (fact? [:env "prod"])
    (effect :deny "No kubectl in production"))
  :effect (effect :allow))

; Combine arg patterns with fact checks
(rule "rm"
  (when (and (anywhere "-r" "--recursive")
             (fact? [:ssh/host (regex "^prod-")]))
    (effect :deny "Recursive delete on production hosts"))
  :effect (effect :allow))
```

## Installation

Install `may-i` and put it on your `PATH`.

When `may-i` runs for the first time, it will create a starter config at
`~/.config/may-i/config.lisp` if one does not already exist.

## Using with Claude Code

Tell Claude Code to use `may-i` as a Bash pre-tool hook in
`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "may-i"
          }
        ]
      }
    ]
  }
}
```

## Using with OpenCode

OpenCode does not currently expose the same hook mechanism, so the practical
approach is to replace the built-in bash tool with a custom one that calls
`may-i eval --json` before execution.

The recommended workflow is to have your agent generate that replacement tool
for your own environment. In broad strokes, it should:

1. call `may-i eval --json` with the pending command
2. pass OpenCode facts such as `:client/opencode` and `:opencode/agent`
3. stop on `deny`
4. fall through to OpenCode's normal approval flow on `ask`
5. execute normally on `allow`

This keeps the integration local and editable, and avoids treating one specific
tool implementation as the canonical solution before OpenCode provides a proper
extension mechanism.

For example, an OpenCode integration can pass facts that let policy distinguish
planning from implementation work:

```bash
may-i eval --fact :client/opencode --fact :opencode/agent=plan 'git add .'
```

## Usage

`may-i` stays out of your way--most of the time it just chugs away, using the
rules you define to make sure your agent behaves.

Keep an eye on the commands you're asked for permission to run; if something is
consistently safe, you can add a rule to `~/.config/may-i/config.lisp` (or ask
your agent to do it for you). After playing this whack-a-mole for a while you
will start to notice fewer prompts.

### Validation & Testing

It's a good idea to write unit tests as you go to keep your config
predictable--write `(check ...)` forms in your rules with example commands. Run
`may-i check` to verify everything works as expected.

```bash
may-i check
```

### Direct Evaluation

Use `may-i eval "CMD..."` to test out how your rules behave with different
inputs.

```bash
may-i eval 'rm -rf /'
```

You can repeat `--fact` to simulate runtime context:

```bash
may-i eval --fact :client/opencode --fact :opencode/agent=build 'git status'
```

### Migration from v1

If you have existing v1 configuration files, use the migration tool to convert
them to v2 syntax:

```bash
may-i migrate ~/.config/may-i/config.lisp
```

**Options:**

- `--dry-run` — Preview changes without modifying the file
- `--diff` — Show a detailed form-by-form diff of what will change
- `--yes` — Skip the confirmation prompt (required for non-TTY usage)

**Interactive Mode:**

When running in a terminal, `may-i migrate` shows a pretty-printed diff of the
changes and prompts for confirmation before applying them. The diff uses a
two-column layout showing before/after forms with fold markers for unchanged
sections:

```
Migration Diff:
─────────────────────────────────────────────────────────────────
│ BEFORE                    │ AFTER                     │
│ (rule (command git)       │ (rule git                 │
│   (effect :allow))        │   (effect :allow))        │
─────────────────────────────────────────────────────────────────
1 forms will change, 0 unchanged

Apply migration? [Y/n]
```

**Features:**

- **Two-column layout** — Side-by-side view on terminals ≥80 columns
- **Inline fallback** — Vertical layout for narrow terminals
- **Fold markers** — Collapsed unchanged sections with ⋮ indicator
- **Pretty-printing** — Consistent formatting via the pp crate
- **Built-in pager** — Interactive scrolling for long diffs (arrow keys, / to search)
- **TTY detection** — Automatically disables pager when piping output

For automated scripts or CI/CD pipelines, use `--yes` to skip the prompt:

```bash
may-i migrate ~/.config/may-i/config.lisp --yes
```

### Global Flags

- `--json` — Output as JSON (works with `eval` and `check`)
- `--config <FILE>` — Use a specific config file (overrides `$MAYI_CONFIG`)

## Configuration

For exact DSL syntax and semantics, see your generated
`~/.config/may-i/config.lisp`. The starter config comments are the best
reference.

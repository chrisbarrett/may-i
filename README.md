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
; sudo unwraps to evaluate its inner command
(rule "sudo" (authorise #cmd))

; ssh unwraps too, but production hosts are off-limits
(rule "ssh"
  (cond ((matches? #host (regex "(^|@).*prod.*"))
         (deny "Production host — no direct recursion"))
        (else (authorise #cmd))))

; Anything reached via ssh is considered immutable
(define immutable (fact? [:via "ssh"]))

(rule "echo" (allow "Local echo is always fine"))

(rule "rm"
  (and immutable
       (deny "Production hosts are immutable")))
```

</details>

## Why use this thing?

Most harnesses require you to approve the shell commands your agents run. This
is a _good thing_, but it limits how much work your agents can do independently
before they get blocked waiting for your approval.

Over time, this trains you to blindly approve prompts without reading them, and
you become tempted to disable these permission systems altogether. The
solutions, like running under docker, or under sandboxes, are pretty
heavyweight.

## How it works

When an agent wants to run a shell command, your harness first runs `may-i` to
authorise it. `may-i` parses the command to find the program calls inside. If
everything looks good, the harness will be able to run your command without
asking you. But if there's something in there that's sus, you get prompted.

- it gives you a proper language for writing shell script permissions policies

- it can see commands embedded inside strings, understand control flow
  constructs, and detect sneaky environment variable dereferencing.

- it can be taught that a program will use its arguments as shell commands
  themselves. This means you can get meaningful approval prompts for
  `ssh $host foo`, `sh -c foo`, `mise exec -- foo`, etc.

- you can write & execute inline tests for your rules so you can be confident
  your policies are working as intended

## A taste of the language

Each rule matches a command and returns a single decision. Use `and`, `or`,
`if`, and `cond` to express conditional logic:

```scheme
(rule "mv"
  (if (anywhere "-f" "--force")
      (ask "Force moves can be destructive")
      (allow)))
```

Wrapper commands like `ssh` and `sudo` can be unwrapped so their inner commands
get evaluated too. The prelude binds `#cmd` to the inner command:

```scheme
(rule "sudo" (authorise #cmd))
```

Named predicates and facts keep things readable as your policy grows. Facts
expose runtime context — which harness is running, whether a command was
reached through `ssh`, etc:

```scheme
(define prod-host
  (fact? [:ssh/host (regex "^prod-")]))

(rule "rm"
  (if (and prod-host (anywhere "-r" "--recursive"))
      (deny "Recursive delete on production hosts")
      (allow)))
```

Run `may-i reference` for the full DSL documentation.

## Installation

Pre-built binaries for macOS and Linux are available on the
[releases page](https://github.com/chrisbarrett/may-i/releases).

If you use Nix, this repo's flake provides an overlay adding `pkgs.may-i`.

### Claude Code

In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "may-i" }]
      }
    ]
  }
}
```

### Codex

In `~/.codex/config.toml`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "may-i"
```

### OpenCode

OpenCode has no hook mechanism. Replace the built-in bash tool with one that
shells out to `may-i eval --json` and interprets the returned decision.

You'll want your implementation to execute something like the command below,
with the shell command to test being passed via stdin:

```bash
may-i eval --fact :client/opencode --fact :opencode/agent=${agent}
```

## Usage

`may-i` stays out of your way — most of the time it just chugs away, using the
rules you define to make sure your agent behaves.

Keep an eye on the commands you're asked for permission to run; if something is
consistently safe, you can add a rule to `~/.config/may-i/config.lisp` (or ask
your agent to do it for you). After playing this whack-a-mole for a while you
will start to notice fewer prompts.

### Testing your policy

Write `(check ...)` forms alongside your rules, then run `may-i check`:

```bash
may-i check
```

Use `may-i eval` to test individual commands:

```bash
may-i eval 'rm -rf /'
may-i eval --fact :opencode/agent=build 'git status'
```

### Repo-local config

When running inside a git repo, `may-i` will search for additional
project-specific files to load:

- `.may-i.lisp`
- `.may-i/**/*.lisp`
- `.may-i.local.lisp`
- `.claude/may-i.lisp`
- `.claude/may-i.local.lisp`

This is helpful for keeping project-specific stuff out of your main
configuration.

> [!IMPORTANT]
> Rules added via these files are ignored unless you approve them by running
> `may-i trust`.

### Rule combination

`may-i` evaluates **every** matching rule for a command and combines the results
under the lattice `:allow < :ask < :deny` — the strictest match wins. The rule
list's order does not affect the decision; it only breaks ties on the `reason`
string (earliest match at the strictest decision supplies the reason).

This means a loaded `:allow` rule **cannot widen** a primary `:deny` for the
same command, even after trust approval, because the lattice combine always
selects `:deny`. Configs that previously relied on "narrow `:allow` before broad
`:deny`" to whitelist exceptions must now express the exception inside a single
rule body, e.g. `(if narrow-pred (allow …) (deny …))`.

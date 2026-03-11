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
(wrapper "ssh" (positional [:ssh/host *] :command+args))
(wrapper "sudo" :command+args)

(defcontext immutable
  (and (has :via/ssh)
       (has [:ssh/host (regex "(^|@).*prod.*")])))

(rule (command "echo")
      (effect :allow "Local echo is always fine"))

(rule (command "rm")
      (context immutable)
      (effect :deny "Production hosts are immutable"))
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

### Checks

Checks are inline tests for your policy. They help keep your config predictable
as it grows, and make it much easier to refactor rules without changing their
behavior by accident.

### Wrappers

Wrappers let `may-i` understand commands that are hidden behind other commands,
such as `ssh`, `nix`, `mise`, or `nohup`. That means you can make decisions
about the inner command instead of treating every wrapper invocation as opaque.

### Facts

Facts are bits of runtime context attached to command evaluation. They let your
policy care about more than the literal command line, such as whether a command
came through `ssh`, which host it targeted, or which agent is running it.

This makes policy much more precise: the same command can be allowed in one
context and escalated in another.

## A small example

For example, you might want to allow `mv` by default, but still require approval
when it uses `--force`.

```scheme
(rule (command "mv")
      (args (if (anywhere "-f" "--force")
                (effect :ask "File moves with -f/--force can be destructive")
                (effect :allow)))
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

That is what facts are for. Some facts come from runtime integrations; others
come from wrappers while `may-i` unwraps a command. Exact syntax and semantics
live in the generated config and starter config comments, but the important idea
is simple: facts let policy follow intent and provenance, not just text.

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

### Global Flags

- `--json` — Output as JSON (works with `eval` and `check`)
- `--config <FILE>` — Use a specific config file (overrides `$MAYI_CONFIG`)

## Configuration

For exact DSL syntax and semantics, see your generated
`~/.config/may-i/config.lisp`. The starter config comments are the best
reference.

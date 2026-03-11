# may-i

`may-i` is a helper for Claude Code that dramatically reduces the number of
permission prompts you get nagged with. It gives you an experience much closer
to running under `--dangerously-skip-permissions` without giving up the safety
of a permission system.

`may-i` is pretty smart, and it knows how to parse Bash accurately before
checking your rules. This means you don't get unnecessarily nagged for
permission just because a command was wrapped in a for-loop. 🎉

## A simple example

For example, you might like to allow Claude to run `mv` whenever it chooses, so
long as it doesn't use `--force`, which could inadvertently delete files.

```scheme
(rule (command "mv")
      (args (if (anywhere "-f" "--force")
                (effect :ask "File moves with -f/--force can be destructive")
                (effect :allow)))
      (check :allow "mv foo bar"
             :ask "mv -f foo bar"))
```

Stack enough of these simple rules up and suddenly you'll find Claude can get a
lot more done without needing your approval.

You can use `(check ...)` forms to define inline unit tests, helping you check
your work and avoid accidental breakages as your rules grow in complexity.

Facts are the runtime context attached to a command evaluation. They are always
namespaced keys like `:via/ssh` or `:opencode/agent`, and they come in two
shapes:

- presence facts: the key is present, like `:via/ssh`
- scalar facts: the key has a string value, like `:opencode/agent = "build"`

Facts can come from integrations at runtime or from wrappers while unwrapping a
command. Rules query them in `(context ...)` with `(has :key)`, `(= :key
"value")`, and `(matches :key "regex")`.

Checks can also simulate runtime facts explicitly when a rule depends on
client-specific state:

```scheme
(rule (command "git")
      (context (= :opencode/agent "build"))
      (effect :allow)
      (check
        (with-facts [[:client/opencode]
                     [:opencode/agent "build"]]
          :allow "git add .")
        (with-facts [[:client/opencode]
                     [:opencode/agent "plan"]]
          :ask "git add .")))
```

`with-facts` takes a vector of fact-entry vectors. Use `[[:key]]` for a
presence fact and `[[:key "value"]]` for a scalar fact. Nested `with-facts`
scopes inherit outer facts, and inner bindings override outer bindings with the
same key.

You can also scope rules to runtime or wrapper-derived context facts. For
example, this only allows `journalctl` when the command was unwrapped from an
`ssh` invocation targeting a production host:

```scheme
(defcontext remote-prod
  (and (has :via/ssh)
       (matches :ssh/host "^prod-")))

(wrapper "ssh"
  (positional [:ssh/host *] :command+args))

(rule (command "journalctl")
      (context remote-prod)
      (effect :allow "Read-only prod inspection over ssh"))
```

OpenCode integrations can also pass the active agent explicitly so policies can
distinguish planning from implementation work:

```scheme
(rule (command "git")
      (context (= :opencode/agent "plan"))
      (effect :ask "Git commands in the plan agent need approval"))
```

Pass runtime facts explicitly when you call `eval`:

```bash
may-i eval --fact :client/opencode --fact :opencode/agent=plan 'git add .'
```

OpenCode currently integrates by invoking `may-i eval` with explicit `--fact`
flags from a custom bash tool. Bare stdin hook mode remains the Claude Code
entrypoint and is organized so additional harnesses can be added later.

## Installation

1. Grab the latest `may-i` build from the GitHub releases, and put it on your
   PATH.

2. tell Claude Code to use `may-i` as a bash tool pre-authorizer in your
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

That's it! `may-i` will create a starter config for you at
`~/.config/may-i/config.lisp` if it doesn't already exist yet--customise it to
your heart's content.

## Usage

`may-i` stays out of your way--most of the time it just chugs away, using the
rules you define to make sure Claude behaves.

Keep an eye on the commands you're asked for permission to run by Claude; if you
think it's safe, you can add a rule to `~/.config/may-i/config.lisp` (or ask
Claude to do it for you). After playing this whack-a-mole for a while you will
start to notice fewer prompts.

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

See the documentation in your generated `~/.config/may-i/config.lisp`.

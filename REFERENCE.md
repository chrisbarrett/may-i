# may-i Reference

`may-i` evaluates shell commands against rules you write to determine whether a
permission prompt is needed.

You can update your rules as you work without restarting your agents. The more
time you spend gardening your rules, the more work your agents can do without
prompting you.

## How it works

`may-i` receives a shell command string, typically via stdin or as an argument.
It uses a shell language parser to extract program calls inside the shell
command, and then runs your rules over all of them to determine whether the
command requires overall approval to proceed.

The most restrictive rule in the command determines the overall need for
approval.

## Configuration language

Configuration for `may-i` is written in an S-expression language. The entrypoint
is `~/.config/may-i/config.lisp` by default.

### `(rule PROG PAT)`

Define automatic allow/ask/deny rules for programs. Rules can inspect arguments
and runtime facts to determine how to proceed.

```lisp
(rule "ls" (effect :allow))

;; Checking for dangerous flags:
(rule "rm"
  (if (flag ["r" "recursive"])
      (effect :ask "Recursive deletion")
    (effect :allow)))

;; More complex branching:
(rule "rm"
  (cond
    ((positional "/")
     (effect :deny "Attempt to delete filesystem root"))

    ((flag ["r" "recursive"])
     (effect :ask "Recursive deletion"))

    (else
     (effect :allow))))
```

### `(check …)`

Define runnable tests for your rules to make sure given commands have the
expected outcome. Worth doing for complex rules with lots of branching.

```lisp
(check :allow "ls -la"
       :ask "rm -rf /tmp/foo"
       :deny "rm -rf /")
```

Run with `may-i check`.

### `(define NAME PAT)`

Define a convenient name for repeated patterns that you can re-use in your
rules.

```lisp
(define prod-host
  (fact? [:ssh/host (regex "^prod-")]))
```

### `(load "FILE")`

Include another config file (path or glob); useful if config gets too long.

```lisp
(load "rules/git.lisp")
(load "rules/*.lisp")
```

Paths are relative to the current file.

### `(parser PROG FORMS…)`

Declare how to parse flags, options and positional args for programs that don't
use the default GNU style.

```lisp
(parser "find" :style single-dash-long)
```

Most commonly needed for programs using the single-dashed `-long` convention.

### `(define-arg-style …)`

Define a custom flag and option-passing convention for use in parsers.

### `(safe-env-vars NAMES…)`

Declare environment variables that may be safely read. By default, only
variables whose values are recovered via static analysis are allowed.

## How rules work

When `may-i` evaluates a shell command, it searches for `rule` definitions
you've written with a matching program name. It then tests the shell command
against each matching rule until it hits an explicit `(effect ...)` form, which
determines whether the command is allowed, blocked, or triggers a permission
prompt.

> [!IMPORTANT]
> A future iteration will make rule evaluation order-independent, such that the
> most restrictive effect always wins.

`may-i` contains a full shell language parser, and it will run you rules over
every command it finds. This means control flow structures, subshells and other
shell constructs are understood and scanned for nested commands.

A rule body either:

- **Allows, asks, or denies** — via `(effect :allow)`, `(effect :ask "…")`, or
  `(effect :deny "…")`. That's the rule's answer.
- **Doesn't match the current command** — for example, an argv pattern that
  doesn't fire, or a conditional whose predicate is false. Evaluation moves on
  to the next rule.

If no rule answers, the default is `:ask` — `may-i` asks you to confirm before
running the command.

> [!TIP]
> Order matters: put deny rules before allow rules so dangerous cases fire
> before a permissive catch-all.

## Deciding whether to prompt for permission

A rule's answer is spelled `(effect DECISION)` or `(effect DECISION REASON)`,
where `DECISION` is one of:

| Decision | When to use                                                                 |
| :------- | :-------------------------------------------------------------------------- |
| `:allow` | The command is safe in this context. No prompt; the agent proceeds.         |
| `:ask`   | The command needs human confirmation. The user sees the reason and chooses. |
| `:deny`  | The command must not run. The agent is told why and cannot proceed.         |

`REASON` is an optional explanatory string shown in traces and permission
prompts. These are helpful for figuring out which branch matched in a complex
set of rules.

```lisp
(effect :allow)
(effect :ask "Recursive deletion — confirm the target")
(effect :deny "No filesystem operations on production hosts")
```

## Matching arguments

The most useful patterns inspect a program's arguments. They return _Allow_ on a
match (so they compose with terminals) and Nil otherwise.

### `(flag NAME)`

Match a boolean flag like `-r` or `--force`.

```lisp
(rule "rm" (and (not (flag "r")) (effect :allow)))   ; allow non-recursive rm
```

`NAME` is a flag spelling without its dashes:

- `"x"` — a short flag (one character). Matches `-x` and combinations like
  `-rfx`.
- `"force"` — a long flag (multi-character). Matches `--force` and
  `--force=VAL`.
- `["f" "force"]` — match either spelling. Use this for short/long pairs.

### `(parameter NAME FORM)`

Match a flag that carries a value, like `--file ./foo` or `-X POST`.
`(parameter …)` consumes both the flag _and_ its value, so anything after them
shifts left in the positional stream.

```lisp
(rule "curl"
  (and (parameter ["X" "request"] "POST") (effect :allow)))
```

`FORM` constrains the captured value:

| Form          | Matches when…                                                 |
| :------------ | :------------------------------------------------------------ |
| `*`           | Any value is present. Use this as a presence check.           |
| `"literal"`   | The value is exactly `"literal"`.                             |
| `(regex "…")` | The value matches the regex.                                  |
| `(may-i *)`   | The value is itself a command line — recurse and re-evaluate. |

### `(positional PAT…)`

Match positional arguments — the ones left over after flags and parameters are
consumed. Patterns are matched in order.

```lisp
(rule "git" (and (positional "push") (effect :ask "Push needs review")))
```

Quantifiers wrap individual patterns so a `(positional …)` can match
variable-length argv:

| Quantifier | Meaning                |
| :--------- | :--------------------- |
| `EXPR`     | Exactly one (default). |
| `(? EXPR)` | Zero or one.           |
| `(+ EXPR)` | One or more.           |
| `(* EXPR)` | Zero or more.          |

### `(exact PAT…)`

Like `(positional …)`, but fails if any positional args are left unconsumed. Use
this when the rule should only fire for an exact-length argv.

### Less commonly: `(anywhere PAT…)` and `(forbidden PAT…)`

`(anywhere PAT…)` matches when any of the listed tokens appears anywhere in argv
— including positions that `(flag …)` and `(positional …)` ignore.
`(forbidden PAT…)` is the inverse: match when none of them appears.

> [!NOTE]
> Reach for `(flag …)` or `(positional …)` first. Save `(anywhere …)` for
> position-agnostic checks — a banned token that should fail the rule wherever
> it shows up.

### Expressions inside patterns

The `PAT` slots above accept richer matchers than bare strings:

| Expression    | Matches…                                                   |
| :------------ | :--------------------------------------------------------- |
| `"string"`    | The literal string.                                        |
| `*`           | Anything.                                                  |
| `(regex "…")` | A regex.                                                   |
| `(or PAT…)`   | Any of the alternatives.                                   |
| `(and PAT…)`  | All of the alternatives (rarely useful on a single token). |
| `(not PAT)`   | The negation.                                              |
| `[:key *]`    | Anything, and bind the matched value as a fact.            |

Binding (`[:key *]`) lets later parts of the rule — or recursive evaluations —
see the captured value as `:key`.

## Composing rule bodies

A rule has exactly one body, so combinators glue patterns and effects together:

| Form            | Result                                                            |
| :-------------- | :---------------------------------------------------------------- |
| `(and EFFECT…)` | All must succeed; short-circuits on Nil. Last child's value wins. |
| `(or EFFECT…)`  | First non-Nil child wins.                                         |
| `(not EFFECT)`  | Swap Allow ↔ Nil. Ask/Deny pass through unchanged.                |

Conditionals branch on a predicate (an arg pattern, `(fact? …)`, a named
`(define …)` reference, or an `and`/`or`/`not` of those):

| Form                              | Behaviour                              |
| :-------------------------------- | :------------------------------------- |
| `(when PRED EFFECT)`              | Run `EFFECT` if `PRED` matches.        |
| `(unless PRED EFFECT)`            | Run `EFFECT` if `PRED` doesn't match.  |
| `(if PRED THEN ELSE)`             | The usual.                             |
| `(cond ((PRED EFF)…) (else EFF))` | Multi-way branch; first matching wins. |

```lisp
(rule "rm"
  (cond
    ((positional "/")
     (effect :deny "Refusing to touch the filesystem root"))

    ((flag ["r" "recursive"])
     (effect :ask "Recursive deletion"))

    (else
     (effect :allow))))
```

## Recursing into wrapped commands

Some commands are wrappers — `sudo`, `ssh`, `bash -c`, `xargs` — and the real
risk is in the inner command. `(may-i *)` evaluates that inner command line
against your rules, with the wrapper recorded as `:via`.

```lisp
;; sudo CMD ARGS… — re-evaluate the inner command.
(rule "sudo"
  (positional . (may-i *)))

;; ssh HOST CMD ARGS… — capture the host as a fact, re-evaluate the rest.
(rule "ssh"
  (positional [:ssh/host *] . (may-i *)))
```

Inside the recursion, `(fact? [:via "sudo"])` lets a downstream rule know it's
running through `sudo`. Combine with bound facts to write rules like "no
recursive `rm` over `ssh`".

`(parameter NAME (may-i *))` does the same for value-bearing flags whose value
is itself a command line — most usefully `bash -c`:

```lisp
(parser "bash" :style gnu (parameter "c" (may-i *)))

;; Now `bash -c "echo hi"` recurses into the rule for echo.
(rule "echo" (effect :allow))
```

## Facts

Facts are runtime context — pieces of information about the environment that
rules can branch on. They come from three places:

- The `--fact` flag passed to `may-i eval`.
- Bindings captured in patterns (`[:ssh/host *]` above).
- Automatic facts set by the engine (`:via` during recursion).

Two shapes:

| Shape           | Meaning                                                  |
| :-------------- | :------------------------------------------------------- |
| `:ci`           | Presence — the key is set, no value.                     |
| `[:env "prod"]` | Value — the key has the given value (or values, plural). |

Query inside a rule with `(fact? …)`:

```lisp
(rule "kubectl"
  (if (fact? [:env "prod"])
      (effect :deny "No kubectl in production")
    (effect :allow)))
```

`(fact? …)` accepts the same expression patterns as argv matchers — literals,
regexes, `or`/`and`/`not` — so you can write `(fact? [:host (regex "^prod-")])`.

Pass facts at evaluation time:

```bash
may-i eval --fact :ci --fact :env=prod 'kubectl get pods'
```

## Reusable predicates

When the same condition shows up in several rules, lift it into a `(define …)`:

```lisp
(define prod-host
  (fact? [:ssh/host (regex "^prod-")]))

(rule "kubectl"
  (if prod-host
      (effect :deny "No kubectl on prod hosts")
    (effect :allow)))

(rule "rm"
  (when (and prod-host (flag ["r" "recursive"]))
    (effect :deny "No recursive rm on prod hosts")))
```

A `(define …)` body is any predicate — `(fact? …)`, an arg pattern, a
combinator, or a reference to another `(define …)`.

## Checks: testing your rules

`(check …)` is your test suite. Each entry pairs an expected decision with a
command line; `may-i check` runs them all and reports failures.

```lisp
(check :allow "ls -la"
       :ask   "rm -rf /tmp/foo"
       :deny  "rm -rf /")
```

To assert behaviour under specific facts, wrap entries in `(with-facts …)`:

```lisp
(check
  (with-facts [[:env "prod"]]
    :deny "kubectl get pods")
  (with-facts [[:env "dev"]]
    :allow "kubectl get pods"))
```

Run them:

```bash
may-i check
```

> [!TIP]
> Add a `(check …)` whenever a rule has more than one branch. Tests catch
> regressions when you tweak rule order or refactor a `(define …)`.

## Splitting config across files

```lisp
(load "rules/git.lisp")              ; load one file
(load "rules/*.lisp")                ; load a glob, in lexical order
```

Paths resolve relative to the file containing the `(load …)` form. Loaded files
can themselves load others. Circular loads are detected and rejected.

## Trusting environment variables

By default the shell parser only expands variables whose values it can recover
through static analysis. To allow others — typically common ones agents rely on
— list them in `(safe-env-vars …)`:

```lisp
(safe-env-vars "HOME" "PWD" "USER" "SHELL" "EDITOR")
```

## Tokenisation: when GNU isn't enough

Most CLIs use GNU-style flag syntax — short `-x`, long `--foo`, `--foo=val`,
combinable shorts. `may-i` assumes this by default, so you usually don't need to
think about tokenisation at all.

A few tools don't:

- `find`, `go`, `terraform`, `java` — single-dashed long options (`-name`,
  `-buildmode=…`).
- `tar`, `ps` — first-token flag bundles (`tar xvzf`).
- `dd` — `key=value` tokens (`if=foo of=bar`).

For these you teach `may-i` how to tokenise their argv with `(parser …)` and
optionally `(define-arg-style …)`.

### `(parser …)` — per-program rules

`(parser …)` says: when you see this program, parse argv under this style, and
treat these specific flags as value-bearing.

```lisp
(parser "find" :style single-dash-long)

(parser "kubectl" :style gnu
  (parameter ["n" "namespace"]))

(parser "dd" :style key-value
  (parameter "if") (parameter "of") (parameter "bs"))

(parser "bash" :style gnu
  (parameter "c" (may-i *)))    ; -c VAL is a sub-command, recurse into it
```

The body declares parser-scoped flags and parameters:

| Form                         | Meaning                                                                                                   |
| :--------------------------- | :-------------------------------------------------------------------------------------------------------- |
| `(flag NAME)`                | `NAME` is a pure boolean flag — it never takes a value.                                                   |
| `(parameter NAME)`           | `NAME` is value-bearing. The tokeniser groups `-NAME VAL` so rules see them paired.                       |
| `(parameter NAME (may-i *))` | As above, plus re-evaluate the captured value as a command line on every invocation (`:via` is recorded). |

`NAME` follows the same rules as `(flag …)` in rules — a string (`"n"` short,
`"namespace"` long) or a `[short long]` vector.

The four prelude styles cover the common cases:

| Style              | What it does                                                                                                                 |
| :----------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| `gnu`              | Default. Short `-x`, long `--foo`, combine `-rf` → `-r -f`, `--foo=val` or `--foo val`.                                      |
| `single-dash-long` | Every `-foo` is a single long flag; no combining. For `find`, `go`, `terraform`, `java`.                                     |
| `legacy-bundle`    | First non-dashed alpha cluster is a flag bundle (`tar xvzf` → `-x -v -z -f`); the rest follows GNU.                          |
| `key-value`        | `key=value` tokens are flag-equivalent; everything else is positional. Bare keys (no `=`) are an error. For `dd`, `ps`, etc. |

Programs without a `(parser …)` use `gnu`.

### `(define-arg-style …)` — your own styles

Bind a parsing style to a name with a property list:

```lisp
;; Java accepts -Xmx=512m, -Xmx 512m, and -Xmx:512m.
(define-arg-style java
  (:overrides gnu :separators (" " "=" ":")))

(parser "java" :style java
  (parameter "Xmx") (parameter "Xms"))
```

The recognised PLIST keys describe how flags are spelled, _not_ which flags a
program has:

| Key                   | Type    | Default  | Meaning                                                                                                          |
| :-------------------- | :------ | :------- | :--------------------------------------------------------------------------------------------------------------- |
| `:long-prefix`        | string  | `"--"`   | Long-flag prefix.                                                                                                |
| `:short-prefix`       | string  | `"-"`    | Short-flag prefix.                                                                                               |
| `:separators`         | (str…)  | `(" ")`  | Separators between a parameter and its value.                                                                    |
| `:combined-shorts`    | bool    | `nil`    | `-rf` expands to `-r -f`.                                                                                        |
| `:first-token-bundle` | bool    | `nil`    | First non-dashed cluster is a flag bundle.                                                                       |
| `:pun`                | keyword | `:allow` | `:allow` ⇒ a bare parameter is treated as value-less. `:error` ⇒ a bare parameter is a tokenisation error.       |
| `:overrides`          | symbol  | _none_   | Inherit from another style; this PLIST replaces only the keys it lists. List-valued keys _replace_, don't merge. |

Cycles in `:overrides` and unknown keys are config-load errors.

> [!NOTE]
> The trace output (`may-i eval`) shows the resolved style and parameter list
> per evaluation, so you can confirm a `(parser …)` is doing what you expect.

## Notes for agents

If you're an agent reading this:

- **Run `may-i check` after every rule edit.** It catches malformed syntax,
  unresolved `(define …)` references, and regressions in `(check …)` cases.
- **Treat the user's rules as authoritative.** On `:ask` or `:deny`, surface the
  reason verbatim and let the user decide.
- **Reach for `(flag …)` and `(parameter …)` first** when matching options. The
  parser-level forms classify tokens correctly across argv shapes, including
  combined short flags like `-rf`.
- **Add a `(parser …)` only when GNU defaults misclassify a tool's argv.** Most
  programs work out of the box.
- **When recursing via `(may-i *)`, land the inner rule first.** Then test with
  `may-i eval 'wrapper inner-cmd …'` to confirm both layers fire.

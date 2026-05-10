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

## The DSL at a glance

Configuration for `may-i` is written in an S-expression language. The entrypoint
is `~/.config/may-i/config.lisp` by default.

| Top-level form              | Purpose                                           |
| :-------------------------- | :------------------------------------------------ |
| `(rule PROG BODY)`          | Decide allow/ask/deny for a program.              |
| `(define NAME EXPR)`        | Bind a reusable predicate.                        |
| `(parser PROG …)`           | Per-program tokenisation rules.                   |
| `(define-arg-style NAME …)` | Custom flag-syntax style.                         |
| `(load "PATH")`             | Include another config file.                      |
| `(safe-env-vars NAMES…)`    | Allow specific env vars in shell expansion.       |
| `(check …)`                 | Test cases for `may-i check`.                     |

A minimal config:

```lisp
(rule "ls" (allow))

(rule "rm"
  (cond
    ((positional "/")            (deny "Filesystem root"))
    ((flag ["r" "recursive"])    (ask  "Recursive deletion"))
    (else                        (allow))))

(rule "sudo" (tail (authorise)))     ; recurse into the wrapped command

(check
  (allow "ls -la")
  (ask   "rm -rf /tmp/foo")
  (deny  "rm -rf /"))
```

## How rules work

When `may-i` evaluates a shell command, it searches for `rule` definitions
you've written with a matching program name. It then tests the shell command
against each matching rule until it hits an explicit decision verb
(`(allow …)`, `(ask …)`, `(deny …)`), which determines whether the command
is allowed, blocked, or triggers a permission prompt.

> [!IMPORTANT]
> A future iteration will make rule evaluation order-independent, such that the
> most restrictive decision always wins.

`may-i` contains a full shell language parser, and it will run you rules over
every command it finds. This means control flow structures, subshells and other
shell constructs are understood and scanned for nested commands.

A rule body either:

- **Allows, asks, or denies** — via `(allow)`, `(ask "…")`, or
  `(deny "…")`. That's the rule's answer.
- **Doesn't match the current command** — for example, an argv pattern that
  doesn't fire, or a conditional whose predicate is false. Evaluation moves on
  to the next rule.

If no rule answers, the default is `:ask` — `may-i` asks you to confirm before
running the command.

> [!TIP]
> Order matters: put deny rules before allow rules so dangerous cases fire
> before a permissive catch-all.

## Decision verbs

A rule's answer is spelled `(VERB)` or `(VERB REASON)`, where `VERB` is
one of:

| Verb      | When to use                                                                 |
| :-------- | :-------------------------------------------------------------------------- |
| `(allow)` | The command is safe in this context. No prompt; the agent proceeds.         |
| `(ask)`   | The command needs human confirmation. The user sees the reason and chooses. |
| `(deny)`  | The command must not run. The agent is told why and cannot proceed.         |

`REASON` is an optional explanatory string shown in traces and permission
prompts. These are helpful for figuring out which branch matched in a complex
set of rules.

```lisp
(allow)
(ask "Recursive deletion — confirm the target")
(deny "No filesystem operations on production hosts")
```

## Matching arguments

The most useful patterns inspect a program's arguments. They return _Allow_ on a
match (so they compose with terminals) and Nil otherwise.

### `(flag NAME)`

Match a boolean flag like `-r` or `--force`.

```lisp
(rule "rm" (and (not (flag "r")) (allow)))   ; allow non-recursive rm
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
  (and (parameter ["X" "request"] "POST") (allow)))
```

`FORM` constrains the captured value:

| Form          | Matches when…                                                 |
| :------------ | :------------------------------------------------------------ |
| `*`           | Any value is present. Use this as a presence check.           |
| `"literal"`   | The value is exactly `"literal"`.                             |
| `(regex "…")` | The value matches the regex.                                  |
| `(authorise)`   | The value is itself a command line — recurse and re-evaluate. |

### `(positional PAT…)`

Match positional arguments — the ones left over after flags and parameters are
consumed. Patterns are matched in order.

```lisp
(rule "git" (and (positional "push") (ask "Push needs review")))
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

A rule has exactly one body, so combinators glue patterns and decisions together:

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
     (deny "Refusing to touch the filesystem root"))

    ((flag ["r" "recursive"])
     (ask "Recursive deletion"))

    (else
     (allow))))
```

## Recursing into wrapped commands

Wrapper commands like `sudo`, `bash -c`, `xargs`, and `find -exec`
carry an inner command line whose risk profile is what really matters.
`(authorise)` evaluates that inner command against your full ruleset,
records the wrapper in `:via`, and propagates the recursed decision.

`(authorise)` is a leaf form — it takes no arguments. The host context
(a parameter, a tail slice, a positional element) supplies the string
the recursion runs on. There are three host contexts:

- `(tail (authorise))` — recurse on the tail slice of argv (sudo, env, …).
- `(parameter NAME (authorise))` — recurse on a parameter's value (bash -c).
- `(positional X (authorise) Y)` — recurse on a single positional element.

A bare `(authorise)` outside a host context is a config-load error.

### Tail recursion: `(tail (authorise))`

For wrappers whose inner command sits after the wrapper's flags — sudo,
env, timeout, nice, watch, etc. — declare the boundary on the parser
side and recurse on the tail in the rule.

```lisp
;; Prelude already ships this declaration; shown for illustration:
(parser "sudo" (style gnu) (tail (after :flags)))

(rule "sudo" (tail (authorise)))
```

`(tail (after :flags))` says "outer slice ends after the last
flag/parameter is consumed; everything after that is the tail." Use
`(tail (after "TOK"))` for wrappers whose inner command starts after a
literal token (e.g. `mise exec -- CMD`).

When the parser declares a tail, all argv matchers in the rule body
(`(flag …)`, `(parameter …)`, `(positional …)`, `(anywhere …)`,
`(forbidden …)`) scope to the **outer** slice. The tail is addressable
only via `(tail (authorise))`. This is what closes the silent-bypass
class: outer matchers can't accidentally claim a flag that belongs to
the inner command.

The prelude ships tail-declaring parsers for `sudo`, `env`, `timeout`,
`time`, `su`, `ionice`, `chrt`, `xargs`, `nice`, `watch`, and `find`
(scope: tools that ship with a regular Linux distribution). Third-party
wrappers like `mise` and `terragrunt` belong in your own config:

```lisp
(parser "mise" (style gnu) (tail (after "--")))
(rule "mise" (when (positional "exec") (tail (authorise))))
```

### Parameter recursion: `(parameter NAME (authorise))`

When a value-bearing flag's value is itself a command line — `bash -c`
is the canonical example — recurse on the captured value:

```lisp
(parser "bash" (style gnu) (parameter "c" (authorise)))

;; Now `bash -c "echo hi"` recurses into the rule for echo.
(rule "echo" (allow))
```

The form appears at parser level (it tells the tokeniser the parameter
is value-bearing AND the value is recursable). It also works at rule
level when you want the recursion to depend on rule conditions.

### Multi-token capture: `find -exec`

`find -exec rm {} \;` and `find -exec rm {} +` carry a multi-token
inner command terminated by `;` or `+`. Declare the parameter with a
`(many-till PAT)` capture-shape on the parser side; the rule then sees
the joined tokens as a single command line.

```lisp
;; Prelude already ships this declaration; shown for illustration:
(parser "find"
  (style single-dash-long)
  (parameter "exec"    (many-till (or ";" "+")))
  (parameter "execdir" (many-till (or ";" "+")))
  (parameter "ok"      (many-till (or ";" "+"))))

(rule "find" (parameter "exec" (authorise)))
;; `find . -exec rm -rf / \;` now routes to the rule for `rm`.
```

Multiple `-exec` clauses each fire the rule body independently; the
strictest decision wins.

### The `:via` fact

Recursion sets `:via` on the inner evaluation's facts, accumulating
through nested wrappers:

```lisp
;; Tighten rm rules under sudo:
(rule "rm"
  (when (and (fact? [:via "sudo"]) (flag ["r" "recursive"]))
    (deny "No recursive rm over sudo")))

;; Or for nested wrappers like sudo ssh host rm …, :via is the set
;; {sudo, ssh}, so test membership of either.
```

`:via` is a set, not a single value — `sudo ssh host rm` accumulates
both `sudo` and `ssh` into `:via`. `(fact? [:via "ssh"])` matches set
membership.

> [!NOTE]
> **Stdin blindspot for `xargs` and `parallel`.** When these tools read
> commands from stdin (the common case), `may-i` cannot statically see
> the inner argv — only the literal command-line arguments. Tail
> recursion authorises what's visible; rules that need to tighten
> further should branch on `(fact? [:via "xargs"])` and refuse without
> confirmation.

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
      (deny "No kubectl in production")
    (allow)))
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
      (deny "No kubectl on prod hosts")
    (allow)))

(rule "rm"
  (when (and prod-host (flag ["r" "recursive"]))
    (deny "No recursive rm on prod hosts")))
```

A `(define …)` body is any predicate — `(fact? …)`, an arg pattern, a
combinator, or a reference to another `(define …)`.

## Checks: testing your rules

`(check …)` is your test suite. Each entry pairs an expected decision with a
command line; `may-i check` runs them all and reports failures.

```lisp
(check (allow "ls -la")
       (ask   "rm -rf /tmp/foo")
       (deny  "rm -rf /"))
```

To assert behaviour under specific facts, wrap entries in `(with-facts …)`.
The fact vector is `[[:key VALUE?] [:key VALUE?] …]`; the body is one or
more decision-tagged check entries.

```lisp
(check
  (with-facts [[:env "prod"]]
    (deny "kubectl get pods"))
  (with-facts [[:env "dev"]]
    (allow "kubectl get pods")))
```

`(with-facts …)` forms can nest — inner facts merge with outer:

```lisp
(check
  (with-facts [[:client/opencode]]
    (with-facts [[:via/ssh]]
      (allow "git push"))))
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
(parser "find" (style single-dash-long))

(parser "kubectl" (style gnu)
  (parameter ["n" "namespace"]))

(parser "dd" (style key-value)
  (parameter "if") (parameter "of") (parameter "bs"))

(parser "bash" (style gnu)
  (parameter "c" (authorise)))    ; -c VAL is a sub-command, recurse into it
```

The body declares parser-scoped flags and parameters:

| Form                         | Meaning                                                                                                   |
| :--------------------------- | :-------------------------------------------------------------------------------------------------------- |
| `(flag NAME)`                | `NAME` is a pure boolean flag — it never takes a value.                                                   |
| `(parameter NAME)`           | `NAME` is value-bearing. The tokeniser groups `-NAME VAL` so rules see them paired.                       |
| `(parameter NAME (authorise))` | As above, plus re-evaluate the captured value as a command line on every invocation (`:via` is recorded). |

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

Bind a parsing style to a name with attribute forms:

```lisp
;; Java accepts -Xmx=512m, -Xmx 512m, and -Xmx:512m.
(define-arg-style java
  (overrides gnu)
  (separators " " "=" ":"))

(parser "java" (style java)
  (parameter "Xmx") (parameter "Xms"))
```

The recognised attribute forms describe how flags are spelled, _not_ which
flags a program has:

| Form                       | Type    | Default  | Meaning                                                                                                            |
| :------------------------- | :------ | :------- | :----------------------------------------------------------------------------------------------------------------- |
| `(long-prefix STRING)`     | string  | `"--"`   | Long-flag prefix.                                                                                                  |
| `(short-prefix STRING)`    | string  | `"-"`    | Short-flag prefix.                                                                                                 |
| `(separators STRING…)`     | str…    | `(" ")`  | Separators between a parameter and its value. Variadic.                                                            |
| `(combined-shorts BOOL)`   | bool    | `nil`    | `-rf` expands to `-r -f`.                                                                                          |
| `(first-token-bundle BOOL)`| bool    | `nil`    | First non-dashed cluster is a flag bundle.                                                                         |
| `(pun KEYWORD)`            | keyword | `:allow` | `:allow` ⇒ a bare parameter is treated as value-less. `:error` ⇒ a bare parameter is a tokenisation error.         |
| `(overrides NAME)`         | atom    | _none_   | Inherit from another style; this declaration replaces only the attributes it lists. List-valued attrs _replace_.   |

Cycles in `(overrides …)` and unknown attribute names are config-load errors.

> [!NOTE]
> The trace output (`may-i eval`) shows the resolved style and parameter list
> per evaluation, so you can confirm a `(parser …)` is doing what you expect.

## CLI commands

`may-i` ships a handful of subcommands. Most users only run `eval`
(via the harness) and `check`; the rest are tooling.

| Command           | Purpose                                                        |
| :---------------- | :------------------------------------------------------------- |
| `may-i eval`      | Evaluate a shell command against your rules.                   |
| `may-i check`     | Run all `(check …)` cases and validate config syntax.          |
| `may-i fmt`       | Reformat configs to canonical layout.                          |
| `may-i migrate`   | Rewrite legacy syntax to canonical form.                       |
| `may-i trust`     | Approve loaded rules so they take effect.                      |
| `may-i parse`     | Print the shell parser's AST for a command.                    |
| `may-i reference` | Render this document.                                          |

All commands accept `--config FILE` (overriding `$MAYI_CONFIG`) and
`--json` for machine-readable output.

### `may-i eval`

Evaluate a shell command and report the decision.

```sh
may-i eval 'rm -rf /tmp/foo'                    # → :ask "Recursive deletion"
may-i eval --fact :ci 'kubectl get pods'         # set a presence fact
may-i eval --fact :env=prod 'kubectl get pods'   # set a value fact
may-i eval --json 'sudo rm /etc/passwd'          # JSON output
```

The default text mode prints a trace of how the decision was reached —
which rule matched, which patterns fired, how recursion routed through
wrappers. JSON mode emits a structured record suitable for harness
integration.

### `may-i check`

Validate config syntax and run every `(check …)` case in the loaded
config (and its `(load …)`'d files). Returns non-zero if any check
fails or the config is malformed.

```sh
may-i check                # report failures
may-i check --verbose      # also print passing cases
```

Run this after every rule edit. Hooks and CI should run it on every
config commit.

### `may-i fmt`

Reformat configs to canonical form. Use it from editors, pre-commit
hooks, or CI. It is the analog of `cargo fmt` for `.lisp`
config files.

```sh
may-i fmt PATH [PATH…]   # format files in place
may-i fmt                # walk (load …) graph from primary config
cat foo.lisp | may-i fmt # stdin → stdout filter
may-i fmt -              # explicit stdin
may-i fmt --check …      # exit 0 (clean) / 1 (would change) / 2 (error); no writes
```

What `fmt` does:

- Pretty-prints whitespace using the column width detected from source.
- Sorts declaration-order-insensitive bodies into a deterministic order:
    - **Parser body**: `(style …)` first, then `(flag …)` declarations
      alphabetised by name, then `(parameter …)` declarations
      alphabetised by name, then `(tail …)` last.
    - **`define-arg-style` body**: attribute forms alphabetised by head
      atom (`combined-shorts` < `long-prefix` < … < `separators`).
    - **`(check …)` body**: cases alphabetised by command string.
    - **Rule bodies**: order **preserved** — rule body forms evaluate
      short-circuit, so order is semantic.
- Sorts the name vector in `(flag VEC)` and `(parameter VEC …)`
  declarations: `(flag ["r" "0"])` becomes `(flag ["0" "r"])`. Vectors
  in any other position (separators, prefixes, rule bodies) are
  order-significant and are left untouched.

What `fmt` does **not** do:

- It never silently rewrites legacy syntax. If the input contains
  forms the canonical loader rejects (e.g. `(effect :allow)`,
  `(may-i *)`), `fmt` formats the input as-is and emits a stderr
  warning suggesting `may-i migrate`. Migration is the explicit
  user-invoked path.
- It does not change rule order or rule body order — both are semantic.

**Comments travel with their owning form.** A comment placed between
two body declarations is owned by the form that follows it; sorting
moves comment + form as a unit. A "section header" comment between
two flags will migrate with whichever flag now sits below it under
the canonical sort order.

Exit codes (also via `--check`):

- `0` — every input matches its canonical form.
- `1` — at least one input would change (`--check` only).
- `2` — parse error, IO error, or other blocking failure.

### `may-i migrate`

Rewrite legacy syntax (v1 wrapper forms, `(effect :decision)`,
`(may-i *)`, dotted-tail continuations, PLIST bodies, etc.) into
canonical form. Walks the `(load …)` graph and rewrites every reachable
file in place.

```sh
may-i migrate              # interactive — preview diff, prompt to apply
may-i migrate --dry-run    # show diff, write nothing
may-i migrate --yes        # apply without prompting
may-i migrate -o OUT IN    # single-file mode: read IN, write OUT
```

Migration emits two warning advisories where relevant:

- Read-only files in the load graph are skipped with a clear notice.
- The wrapper-boundary semantic fix may change behaviour for rules
  over `sudo`/`xargs`/etc. — migrate emits a warning naming the
  affected commands and recommends re-running `may-i check`.

Trust hashes for syntactic-only rewrites auto-update under the same
approval; users see a notice but don't re-approve.

### `may-i trust`

Loaded rules from `(load …)`'d files are inert until approved. Inspect
or grant trust:

```sh
may-i trust                  # list pending approvals
may-i trust PROGRAM          # approve rules covering PROGRAM
may-i trust --all            # approve everything pending
```

Approvals are keyed by canonical-form hash, so reformatting (or
running `may-i fmt`) keeps a rule trusted but reordering or editing it
requires re-approval.

### `may-i parse`

Print the shell parser's AST for a command — useful for debugging why
a rule did or didn't match. No config evaluation.

```sh
may-i parse 'find . -name "*.bak" -delete'
may-i parse --file shellscript.sh
```

### `may-i reference`

Render this document with terminal pagination. The same content as
`REFERENCE.md` in the repo.


pre-commit hooks, or CI. It is the analog of `cargo fmt` for `.lisp`
config files.

```sh
may-i fmt PATH [PATH…]   # format files in place
may-i fmt                # walk (load …) graph from primary config
cat foo.lisp | may-i fmt # stdin → stdout filter
may-i fmt -              # explicit stdin
may-i fmt --check …      # exit 0 (clean) / 1 (would change) / 2 (error); no writes
```

What `fmt` does:

- Pretty-prints whitespace using the column width detected from source.
- Sorts declaration-order-insensitive bodies into a deterministic order:
    - **Parser body**: `(style …)` first, then `(flag …)` declarations
      alphabetised by name, then `(parameter …)` declarations
      alphabetised by name, then `(tail …)` last.
    - **`define-arg-style` body**: attribute forms alphabetised by head
      atom (`combined-shorts` < `long-prefix` < … < `separators`).
    - **`(check …)` body**: cases alphabetised by command string.
    - **Rule bodies**: order **preserved** — rule body forms evaluate
      short-circuit, so order is semantic.
- Sorts the name vector in `(flag VEC)` and `(parameter VEC …)`
  declarations: `(flag ["r" "0"])` becomes `(flag ["0" "r"])`. Vectors
  in any other position (separators, prefixes, rule bodies) are
  order-significant and are left untouched.

What `fmt` does **not** do:

- It never silently rewrites legacy syntax. If the input contains
  forms the canonical loader rejects (e.g. `(effect :allow)`,
  `(may-i *)`), `fmt` formats the input as-is and emits a stderr
  warning suggesting `may-i migrate`. Migration is the explicit
  user-invoked path.
- It does not change rule order or rule body order — both are semantic.

**Comments travel with their owning form.** A comment placed between
two body declarations is owned by the form that follows it; sorting
moves comment + form as a unit. A "section header" comment between
two flags will migrate with whichever flag now sits below it under
the canonical sort order.

Exit codes (also via `--check`):

- `0` — every input matches its canonical form.
- `1` — at least one input would change (`--check` only).
- `2` — parse error, IO error, or other blocking failure.

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
- **When recursing via `(authorise)`, land the inner rule first.** Then test with
  `may-i eval 'wrapper inner-cmd …'` to confirm both layers fire.

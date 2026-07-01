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
| `(env NAME DECISION)`       | Govern an env var: lift the write floor, or taint it. |
| `(redirect PAT? DECISION)`  | Govern write-redirect targets (lift the floor, or tighten). |
| `(check …)`                 | Test cases for `may-i check`.                     |
| `(audit …)`                 | Persist a JSONL trail of decisions (Audit log).   |

A minimal config:

```lisp
(rule "ls" (allow))

(rule "rm"
  (cond
    ((positional "/")            (deny "Filesystem root"))
    ((flag ["r" "recursive"])    (ask  "Recursive deletion"))
    (else                        (allow))))

(rule "sudo" (authorise #cmd))       ; recurse into the wrapped command

(check
  (allow "ls -la")
  (ask   "rm -rf /tmp/foo")
  (deny  "rm -rf /"))
```

## How rules resolve

When `may-i` evaluates a shell command, it picks the *applicable set* of
rules — every `(rule …)` declaration whose program name matches — and
evaluates each one. Rule order in the file does not matter.

Every rule that produces an answer contributes; the strictest answer wins,
under the ordering **deny > ask > allow**. If two or more rules tie at the
strictest level, their distinct reasons are sorted alphabetically and joined
with `"; "` so the result is the same no matter how you arranged the rules.

`may-i` contains a full shell language parser, and it will run your rules over
every command it finds. This means control flow structures, subshells and other
shell constructs are understood and scanned for nested commands.

A rule body either:

- **Allows, asks, or denies** — via `(allow)`, `(ask "…")`, or
  `(deny "…")`. That's the rule's answer, and it joins the strictest-wins
  vote for the command.
- **Doesn't match the current command** — for example, an argv pattern that
  doesn't fire, or a conditional whose predicate is false. The rule produces
  no answer and drops out of the vote.

If no rule answers, the default is `:ask` — `may-i` asks you to confirm before
running the command.

> [!TIP]
> A defensive `(deny …)` rule can sit anywhere in the file (or in a
> separate `(load …)`-ed file) — its decision will still dominate any
> `(allow …)` that matches the same command.

### Composing rules from multiple sources

Because rule evaluation is order-independent, splitting rules across
`(load …)` files — or pulling in a shared ruleset from elsewhere — is safe:
adding a `(load …)` line cannot change the meaning of any rule already in
the file. The strictest decision still wins regardless of which file each
rule came from.

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

The most useful patterns inspect a program's arguments. They return _allow_ on
a match (so they compose with decisions) and no-match otherwise.

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

| Quantifier  | Meaning                |
| :---------- | :--------------------- |
| `EXPR`      | Exactly one (default). |
| `(? EXPR…)` | Zero or one.           |
| `(+ EXPR…)` | One or more.           |
| `(* EXPR…)` | Zero or more.          |

A quantifier head may wrap **more than one** sub-pattern. Several sub-patterns
form an implicit **sequence**: the whole sub-sequence is the quantified unit,
matched against consecutive positional args, and `+`/`*` repeat the whole
sub-sequence. Sub-patterns may themselves be quantifiers, so sequences nest.

```lisp
;; Optional `run`, then (only after run) an optional `--`:
;;   matches «», «run», or «run --» — but never a bare «--».
(rule "terragrunt"
  (and (positional (? "run" (? "--")) (or "state" "output")) (allow)))

;; Repeat a whole option/value sub-sequence:
(positional (+ "--opt" *))   ; matches «--opt a --opt b»
```

A binding inside a repeated group collects every matched value into a set (it
does not pair values across occurrences).

> [!IMPORTANT]
> `(positional …)` matches the **residual** — the tokens left after flags and
> parameters are consumed. For a flag the parser does not declare, the gnu
> tokeniser must _guess_ whether it takes a value (see [Declaring flags so the
> tokeniser doesn't guess](#declaring-flags-so-the-tokeniser-doesnt-guess)), and
> a wrong guess can shift a positional out of the residual. So a security
> **deny-guard belongs on `(flag …)` or `(anywhere …)`**, which scan the raw
> argv and are immune to arity guessing — never on `(positional …)`, which sees
> the consumption-sensitive residual. Use `(positional …)` for routing and
> allow-listing, not as the last line of defence.

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

A rule has exactly one body, so `and`/`or`/`not` glue patterns and decisions together:

| Form          | Result                                                                  |
| :------------ | :---------------------------------------------------------------------- |
| `(and EXPR…)` | All must match; short-circuits on the first no-match. Last child wins.  |
| `(or EXPR…)`  | First matching child wins.                                              |
| `(not EXPR)`  | Swap allow ↔ no-match. ask/deny pass through unchanged.                 |

Conditionals branch on a predicate (an argv pattern, `(fact? …)`, a named
`(define …)` reference, or an `and`/`or`/`not` of those):

| Form                                | Behaviour                              |
| :---------------------------------- | :------------------------------------- |
| `(when PRED EXPR)`                  | Run `EXPR` if `PRED` matches.          |
| `(unless PRED EXPR)`                | Run `EXPR` if `PRED` doesn't match.    |
| `(if PRED THEN ELSE)`               | The usual.                             |
| `(cond ((PRED EXPR)…) (else EXPR))` | Multi-way branch; first matching wins. |

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
`(authorise #var)` evaluates that inner command against your full
ruleset, records the wrapper in `:via`, and propagates the recursed
decision.

`(authorise)` is no longer a leaf — it takes exactly one binding
reference. The parser-side declaration names the recurse target with
a `#var` sigil; the rule body consumes that name. The shape is:

```lisp
(parser PROG (style …) (flags MODE) (rest #cmd) …)   ; parser binds
(rule PROG (authorise #cmd))                          ; rule consumes
```

Binding names are written `#name` — a fourth sigil class alongside
`:keyword`, bare-symbol, and `"string"`. The leading `#` is part of
the surface syntax only; programs reference bindings by their bare
name in error messages and traces.

### Flag-scanning mode: `(flags MODE)`

Every parser body declares its flag-scanning mode. Three modes:

- `(flags posix)` — outer flags appear only before the first
  positional; the first non-flag token stops outer scanning. Matches
  `POSIXLY_CORRECT` semantics. Used by sudo, env, timeout, xargs,
  nice, watch, su, ionice, chrt, nohup, strace.
- `(flags permute)` — outer flags may appear anywhere; the outer
  parser peels declared flags and parameters wherever they occur.
  Matches GNU getopt's permuting default. Used by git, ls, cp, and
  most non-wrapper tools. The default when `(flags …)` is omitted.
- `(flags (until STR…))` — outer parser scans up to the first
  occurrence of any listed boundary token; the boundary token is
  consumed and dropped. Used by `mise --` and
  `nix --command|-c`.

### Declaring flags so the tokeniser doesn't guess

`(flag NAME)` and `(parameter NAME …)` are not only rule-body matchers —
they are also **parser-body declaration kinds**. Declaring a flag on the
parser fixes its arity, so the tokeniser never has to guess:

```lisp
;; `--release` and `-v` are boolean; `--bin` takes a value.
(parser "cargo"
  (style gnu)
  (flag "release")
  (flag "v")
  (parameter "bin"))
```

- `(flag NAME)` — declares a **value-less** (boolean) flag. The token after
  it stays in the positional residual.
- `(parameter NAME …)` — declares a **value-bearing** flag. It consumes the
  next token as its value regardless of that token's shape (author-asserted
  arity), so `(parameter "bin")` makes `--bin --foo` capture `--foo`.

#### The value-shape rule for undeclared long flags

Under gnu-shaped styles, when a `--long` flag is **neither** declared as a
`(parameter …)` **nor** referenced by one in a matching rule, its arity is
unknown and the tokeniser guesses: it consumes the next token as the flag's
value **only when that token is a plausible value** —

- **not consumed** (left in the residual): a flag-shaped token — one that
  begins with `--`/`-` and whose next character is a letter — and the `--`
  flag-stop, which is never absorbed.
- **consumed** as the value: a prefix-less token (`report.txt`), a
  negative-number token (`-5`), or a bare `-`.

So `tool --output report.txt` consumes `report.txt`, while
`cargo run --quiet --bin may-i -- eval` leaves `--quiet` value-less (its
successor `--bin` is flag-shaped) and keeps the `run … -- … eval` adjacency.
A boolean flag immediately before a bare subcommand (`cargo --release build`)
**cannot** be told apart by shape from a value flag, so the guess still
consumes `build`; declare `(flag "release")` to keep `build` in the residual.

Every such guess is surfaced as an **arity-guess Advisory** in the trace
(naming the flag and the consumed token) so it is observable, not silent. The
Advisory never changes the decision. See the deny-guard guidance under
[`(positional …)`](#positional-pat) — guards that must hold belong on
`(flag …)` / `(anywhere …)`, which read raw argv.

### Tail recursion: `(rest #cmd)` + `(authorise #cmd)`

For wrappers whose inner command sits after the wrapper's flags —
sudo, env, timeout, nice, watch, etc. — declare the recurse target
with `(rest #var)` on the parser side and `(authorise #var)` on the
rule side:

```lisp
;; Simplified illustration. The shipped prelude additionally declares
;; sudo's value-taking flags (-u, -p, …) as (parameter …) so they
;; consume their argument instead of swallowing the inner command:
(parser "sudo" (style gnu) (flags posix) (rest #cmd))

(rule "sudo" (authorise #cmd))
```

`(flags posix)` says "outer slice ends after the last flag/parameter
is consumed; everything after that is the rest." `(rest #cmd)` names
that unconsumed tail so the rule body can recurse via
`(authorise #cmd)`.

For wrappers whose inner command starts after a literal token, use
`(flags (until "TOK"))`; for multi-spelling boundaries, list every
boundary token:

```lisp
;; The prelude's nix parser — both `--command` and `-c` qualify:
(parser "nix"
  (style gnu)
  (flags (until "--command" "-c"))
  (rest #cmd))
```

The engine splits at the first occurrence of *any* listed token; the
matched token is consumed.

Rule-body argv matchers (`(flag …)`, `(parameter …)`, `(positional
…)`, `(anywhere …)`, `(forbidden …)`) scope to the outer slice — they
never see the rest binding's tokens. This is what closes the
silent-bypass class: outer matchers can't accidentally claim a flag
that belongs to the inner command.

When the parser declares a binding but the parser produces no value
for it — boundary token absent under `(flags (until …))`, parameter
not present, positional unbound — `(authorise #var)` returns
no-match. The rule does not fire, and evaluation continues with
subsequent rules. This prevents a missing or mis-spelled boundary
from silently re-running the rule on the full argv.

#### Worked example: `mise exec -- rm -rf /tmp/foo`

The prelude ships mise as `(flags (until "--")) (rest #cmd)`; a
hand-written equivalent looks like:

```lisp
;; Step 1: parser binds the recurse target. Outer parsing honours
;; GNU style up to `--`; tokens after `--` bind to `#cmd`, verbatim,
;; with no flag interpretation.
(parser "mise" (style gnu) (flags (until "--")) (rest #cmd))

;; Step 2: rule body. The (positional "exec") matches against the
;; outer slice — mise's own positional args before `--`. (authorise
;; #cmd) recurses on the bound value as a fresh command.
(rule "mise"
  (when (positional "exec") (authorise #cmd)))
```

What this looks like at each stage for `mise exec -- rm -rf /tmp/foo`:

```
argv after tokeniser-split:
  outer  = [mise, exec]           ← parsed under GNU style
  #cmd   = [rm, -rf, /tmp/foo]    ← verbatim, bound by (rest …)

rule body evaluation:
  (positional "exec")             ← matches outer slice → ok
  (authorise #cmd)                ← joins #cmd, parses as command,
                                    recurses into the rule for `rm`

inner evaluation receives:
  command = rm
  argv    = [-rf, /tmp/foo]
  facts   = {:via "mise"}         ← so rules can branch on (fact? :via "mise")
```

Without the parser declaration, `(positional "exec")` would also
match on `mise exec` (because mise has no other args to confuse it),
but the silent-bypass class reasserts itself: the outer GNU tokeniser
would swallow `-rf` as if it were a mise flag, and the recurse would
walk `rm /tmp/foo` instead of `rm -rf /tmp/foo`. The parser
declaration is what makes the rule's promise hold.

The prelude ships parsers for sudo, env, time, su, ionice, chrt,
nohup, xargs, timeout, nice, watch, strace, mise, nix, ssh, direnv,
bash, nix-shell, and find. Scope: tools that ship with a regular
Linux distribution, plus widely-used wrappers whose argv semantics
are silent-bypass footguns. For anything else, write the parser
yourself.

### Parameter recursion: `(parameter NAME #var)` + `(authorise #var)`

When a value-bearing flag's value is itself a command line — `bash
-c` is the canonical example — bind the captured value on the parser
side and recurse from the rule:

```lisp
;; Prelude already ships this; shown for illustration:
(parser "bash" (style gnu) (flags permute) (parameter "c" #cmd))

(rule "bash" (authorise #cmd))
;; Now `bash -c "echo hi"` recurses into the rule for echo.
```

The `#cmd` binding is value-bearing: it carries the captured `-c`
argument. Rule-side `(authorise #cmd)` lifts it into a command line
and recurses.

### Multi-token capture: `find -exec`

`find -exec rm {} \;` and `find -exec rm {} +` carry a multi-token
inner command terminated by `;` or `+`. Declare the parameter with a
`(many-till PAT)` capture-shape and bind it to a `#var`; the
captured token list joins with single spaces when recursing.

```lisp
;; Prelude already ships this declaration; shown for illustration:
(parser "find"
  (style single-dash-long)
  (flags permute)
  (parameter "exec"    (many-till (or ";" "+")) #exec)
  (parameter "execdir" (many-till (or ";" "+")) #execdir)
  (parameter "ok"      (many-till (or ";" "+")) #ok))

(rule "find" (authorise #exec))
;; `find . -exec rm -rf / \;` now routes to the rule for `rm`.
```

Multiple `-exec` clauses each fire the rule body independently; the
strictest decision wins.

### Positional bindings

Parsers can name positional slots so rules can match them by binding:

```lisp
;; Prelude ssh declaration (simplified — the shipped parser also
;; declares ssh's value-taking flags as (parameter …) so e.g. `-p 22`
;; doesn't bind `22` to #host). The host token is bound to #host so
;; rules can branch on it via (matches? #host …).
(parser "ssh"
  (style gnu)
  (flags posix)
  (positional #host (regex "^[^-].*"))
  (rest #cmd))

(rule "ssh"
  (when (matches? #host (regex "^prod-"))
    (deny "no SSH to production")))
```

A positional declaration `(positional [#var] PAT [QUANT])` carries
an optional `#var` binding, a required pattern, and an optional
quantifier (`one` default; `?`, `*`, `+` available). Tokens matched
by a declared positional stay positionally visible to rule-body
`(positional …)` matchers and bind to `#var` for predicate use.

### Rule-body predicates: `(bound? #var)` and `(matches? #var PAT)`

`(bound? #var)` is true iff `#var` resolved to a non-empty value in
the active parser environment. Useful for branching on optional
positionals and parameters.

`(matches? #var PAT)` matches `PAT` against the string coercion of
`#var`'s value (single tokens as-is; multi-token captures
space-joined). Lifts a bound value into the predicate algebra.

### Rule-body quantifiers: `(every? #var PRED)` and `(some? #var PRED)`

When a parser binds a list of values — a `(parameter NAME (set #var))`
or a repeating `(positional #var PAT *)` / `(positional #var PAT +)` —
fold a predicate over it:

- `(every? #var PRED)` matches iff **every** value satisfies `PRED`. An
  empty list matches (vacuously true).
- `(some? #var PRED)` matches iff **at least one** value satisfies
  `PRED`. An empty list does not match.

The binding comes first, the predicate second — like every other
binding form (`(authorise #var)`, `(matches? #var PAT)`). `PRED` is the
same single-value pattern sublanguage as `(matches? …)`: a literal, a
`(regex …)`, `*`, `(or …)`/`(and …)`/`(not …)`, or a fact-binding
`[:k *]`.

```lisp
;; Allow recursive rm only when every path is under /tmp.
(parser "rm" (style gnu) (flags posix)
  (positional #paths (regex "^/tmp/") *))

(rule "rm"
  (when (flag ["r" "recursive"])
    (cond
      ((every? #paths (regex "^/tmp/"))  (allow "Tmp paths only"))
      (else                              (ask  "Recursive deletion")))))

;; Ask before an ssh that sets a ProxyCommand.
(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))

(rule "ssh"
  (when (some? #opts (regex "^ProxyCommand="))
    (ask "review ProxyCommand")))
```

A fact-binding inside the predicate accumulates matched values into a
fact: `(every? #opts [:ssh/opt *])` records each value under `:ssh/opt`
when the whole list matches; `(some? #opts (and (regex "^ProxyCommand=")
[:ssh/proxy *]))` records just the matching values.

Using `(every? …)` / `(some? …)` on a binding that is **not** a list —
or `(authorise …)` on something that is not a command line — is
reported when the config loads, naming what the binding is and where it
was declared, with a suggested rewrite.

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
> the inner argv — only the literal command-line arguments.
> `(authorise #cmd)` authorises what's visible; rules that need to
> tighten further should branch on `(fact? [:via "xargs"])` and refuse
> without confirmation.

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
(rule "systemctl"
  (if (fact? [:env "prod"])
      (deny "No systemctl in production")
    (allow)))
```

`(fact? …)` accepts the same expression patterns as argv matchers — literals,
regexes, `or`/`and`/`not` — so you can write `(fact? [:host (regex "^prod-")])`.

Pass facts at evaluation time:

```bash
may-i eval --fact :ci --fact :env=prod 'systemctl restart nginx'
```

## Reusable predicates

When the same condition shows up in several rules, lift it into a `(define …)`:

```lisp
(define prod-host
  (fact? [:ssh/host (regex "^prod-")]))

(rule "systemctl"
  (if prod-host
      (deny "No systemctl on prod hosts")
    (allow)))

(rule "rm"
  (when (and prod-host (flag ["r" "recursive"]))
    (deny "No recursive rm on prod hosts")))
```

A `(define …)` body is any predicate — `(fact? …)`, an argv pattern, an
`and`/`or`/`not` of those, or a reference to another `(define …)`.

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
    (deny "systemctl restart nginx"))
  (with-facts [[:env "dev"]]
    (allow "systemctl restart nginx")))
```

`(with-facts …)` forms can nest — inner facts merge with outer:

```lisp
(check
  (with-facts [[:client/opencode]]
    (with-facts [[:via/ssh]]
      (allow "git push"))))
```

To simulate the **entry environment** (which `check` otherwise treats as empty —
it is hermetic), wrap entries in `(with-env [NAME …] …)`. The vector lists
names only (no values); the body is one or more check entries. Names nest and
merge by union, and `(with-env …)` composes with `(with-facts …)` in either
order:

```lisp
(check
  (with-env ["PATH"]
    (ask "PATH=/evil:$PATH; ls"))        ; PATH present → reaches a child → :ask
  (allow "MY_TMP=/x; ls"))               ; MY_TMP absent → shell-local → :allow
```

A `(scope …)`-dependent `(env …)` rule with no `(with-env …)` coverage for its
name draws a `warn` advisory from `may-i check`: the empty default never
exercises the always-exported names (`PATH`, `LD_*`, …) the rule guards. The
advisory does not fail the run.

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

## Capabilities: `(env …)` and `(redirect …)`

A **capability** attaches a decision to a feature of the *shell language* — a
redirect-write target or an environment variable — instead of to a command. It
contributes that decision to the same strictest-wins combination as the
command's own rule, so it governs an O(1) shell concern without annotating
every rule. Because `:allow` is the lattice bottom, a capability `allow` only
*releases a floor* another unit imposed; it never authorises a command its rule
didn't already allow. A capability `deny`/`ask` actively tightens.

Capabilities are honoured only from the primary config; in a `(load …)`-ed or
repo-local file they are inert until you approve their trust scope (`:env` /
`:redirect`) with `may-i trust`.

### Trusting environment variables: `(env NAME DECISION)`

Environment use splits into two positions, with opposite defaults:

- **Write** — a write that **reaches a child process** — defaults to `:ask`,
  because a write like `LD_PRELOAD=…` changes what executes. A write reaches a
  child when it is a command prefix (`NAME=VALUE cmd`), an exported declaration
  (`export NAME=…`, `declare -x …`), a bare reassignment (`NAME=…` as its own
  command) of a name present in the **entry environment** (bash keeps the export
  attribute, so the new value re-crosses), or any assignment while `set -a` /
  `set -o allexport` is active. A purely shell-local write — a bare assignment
  of a name *not* in the entry environment, a `declare`/`local`/`readonly`
  without `-x`, or an array literal — does **not** floor; it sets a shell
  variable no child inherits. `(env NAME (allow))` lifts the floor (it is
  exactly a `(safe-env-vars NAME)` entry); `(env NAME (ask|deny))` tightens it.
- **Read** — a `$NAME` expansion in a command argument — defaults to `:allow`.
  `(env NAME (ask|deny))` *taints* the name: whenever `$NAME` appears in argv,
  it contributes `:ask`/`:deny`. This is structural secret-exfiltration defence
  — it fires on the token in the parsed command, never tracing the value to a
  sink. A program that reads its secret from its *own* environment (`aws`,
  `gh`) never puts `$NAME` in argv, so it is unaffected. `(env NAME (allow))`
  has no effect in read position.

```lisp
(safe-env-vars "HOME" "PWD" "USER" "SHELL" "EDITOR")   ; allowlist sugar

(env "GIT_PAGER"  (allow))                ; same as adding it to safe-env-vars
(env "LD_PRELOAD" (deny  "code injection via the loader"))
(env "AWS_TOKEN"  (ask   "secret — confirm before it enters a command"))
(env "AWS_TOKEN"  (if (fact? :ci) (deny "no secrets in CI logs") (ask)))

(env (or "AWS_TOKEN" "GH_TOKEN" "NPM_TOKEN") (deny))   ; one decision, many names
```

The subject is a single name or an `(or NAME…)` set that applies the same
decision to every listed name — handy for tainting a family of secrets at once.

`(safe-env-vars "A" "B")` is exactly `(env "A" (allow)) (env "B" (allow))`;
`may-i migrate` rewrites the former to the latter, and because both lower to
the same allowlist the migration preserves your trust approval (Class A).

The DECISION accepts the fact-conditioned subset of the rule-body language —
the decision verbs, `(and|or|not …)`, `(if|when|unless|cond …)`, and
`(fact? …)`. Argv matchers (`(positional …)`, `(flag …)`, `(authorise …)`, …)
are rejected at load time: a capability is command-agnostic and has no argv to
match against.

Inside an `(env …)` decision you may also branch on **how** a write crosses the
boundary with the `(scope …)` predicate. Its values are `prefix`, `export`,
`bare`, and the derived `reaches-child` (the disjunction of all reaching forms):

```lisp
(env "EDITOR" (when (scope reaches-child) (ask)))   ; ask only when it reaches a child
(env "PATH"   (when (scope bare) (deny)))           ; deny a bare re-export specifically
```

`(scope …)` is valid only inside an `(env …)` decision — using it in a rule body
or a `(redirect …)` decision is rejected at load time.

### The entry environment

Whether a *bare* reassignment reaches a child depends on the **entry
environment** — the names-only snapshot of the exported environment at the start
of the invocation. It carries names only, never values. Its source depends on
the invocation mode:

- `may-i hook` captures the live process environment as its first action.
- `may-i eval` defaults to an **empty** entry environment. `--env NAME`
  (repeatable) adds a hypothetical name; `--inherit-env` captures this process's
  exported names (for reproducing a live hook decision). The two combine.
- `may-i check` is **hermetic**: it never reads the host environment; a case
  declares names with `(with-env [NAME …] …)` (see *Checks*).

```sh
may-i eval --env PATH 'PATH=/evil:$PATH; ls'      # PATH present → reaches → :ask
may-i eval 'PATH=/evil:$PATH; ls'                 # PATH absent  → shell-local → :allow
may-i eval --inherit-env 'LD_PRELOAD=/x echo hi'  # reproduce a live decision locally
```

### Trusting redirect targets: `(redirect PAT? DECISION)`

A **write** redirection to a non-standard file target (`> f`, `>> f`, `>| f`)
floors to `:ask` by default — the write is invisible to the command's rule.
`(redirect PAT DECISION)` governs such targets by matching `PAT` (any Pattern:
`"lit"`, `(regex …)`, `(or …)`, …) against the target; an omitted pattern
matches any target. Read redirections (`<`, `<<<`, here-docs) perform no write
and never floor.

```lisp
(redirect (regex "^/tmp/") (allow))       ; writes under /tmp don't prompt
(redirect "/etc/hosts"     (deny))        ; never write the hosts file
(redirect (allow))                        ; any write target is fine
```

An expansion-bearing target (`> /tmp/$NAME`) can never satisfy a capability
toward `:allow` — its runtime value is unknown — so it floors regardless of a
matching `(allow)`.

## The Audit log: `(audit …)`

The Audit log is an append-only JSONL trail of evaluation outcomes — one record
per evaluation — for after-the-fact forensics: _which commands failed to parse,
asked, or were denied?_ It changes no decision; it only records.

```lisp
(audit (threshold :ask))                  ; record asks and denials
(audit (threshold :deny) (file "/var/log/may-i/audit.jsonl"))
```

The form takes two optional, head-keyed sub-forms (alist-style, like
`(define-arg-style …)`):

- `(threshold :off|:deny|:ask|:all)` — which outcomes to record, ordered by
  strictness. `:off` (the default) disables the log; `:deny` records denials;
  `:ask` records asks and denials; `:all` records allows, asks, and denials.
  There is no separate enable/disable knob — `:off` is the disabled state.
  **A command that fails to parse is always recorded** at any non-`:off`
  threshold (its decision floors to `:ask`, and that is exactly the forensic
  case you want).
- `(file "PATH")` — where to write. Defaults to the location below.

**Primary-config only.** `(audit …)` is honoured only from your primary config.
An `(audit …)` form in a `(load …)`-ed or repo-local file is a hard load error:
a loaded source must not be able to silence or redirect the trail.

### Precedence and the environment

Each setting resolves independently, highest to lowest:
`--audit-* flag > MAYI_AUDIT_* env var > (audit …) form > default`. Overriding
one field leaves the other untouched.

| Setting     | Flag                  | Environment             |
| :---------- | :-------------------- | :---------------------- |
| threshold   | `--audit-threshold`   | `MAYI_AUDIT_THRESHOLD`  |
| file        | `--audit-file`        | `MAYI_AUDIT_FILE`       |

On the CLI and in the environment the threshold is a **bare string** (`ask`),
not the keyword spelling (`:ask`). The environment tier exists because hook mode
is stdin-driven and cannot take flags — set `MAYI_AUDIT_THRESHOLD` to configure
auditing for the hook path.

Only the `eval` and `hook` paths write records; `check` never does (it replays
synthetic test commands and never blocks).

### Record fields

Each record is one line of JSON: a schema version (`v`), an RFC 3339 timestamp
(`ts`), the invocation `mode` (`eval`/`hook`), the `harness` (when known), the
verbatim `command`, the `decision`, the `reason`, the outcome `source`
(`rule` / `trust-block` / `parse-floor`), `parse_ok`, the parse `diagnostic`
(when it failed), the canonical-form hashes of the deciding `rules`, the
`config` path, and `cwd` (when known). Query it with `jq`:

```sh
jq 'select(.decision == "deny") | .command' ~/.local/state/may-i/audit.jsonl
```

### Location, permissions, and rolling

The default file is `$XDG_STATE_HOME/may-i/audit.jsonl`, falling back to
`~/.local/state/may-i/audit.jsonl`. The directory is created `0700` and the
file `0600`.

> **The trail records verbatim commands** — treat it as a secret surface. It is
> opt-in (`:off` by default), the `0600`/`0700` modes keep it owner-only, and
> `(file "/dev/null")` is an escape hatch that records nowhere.

`may-i` does not rotate the file. Delegate rolling to `logrotate` with
`copytruncate` (each record is appended in a single `O_APPEND` write, so
truncation never tears a line):

```
/home/you/.local/state/may-i/audit.jsonl {
    weekly
    rotate 8
    copytruncate
    compress
}
```

> **NFS caveat.** The single-write append-atomicity guarantee holds on a local
> filesystem. On NFS, concurrent writers may interleave; a local
> `~/.local/state` path is the supported case.

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

(parser "make" (style gnu)
  (parameter ["f" "file"]))

(parser "dd" (style key-value)
  (parameter "if") (parameter "of") (parameter "bs"))

(parser "bash" (style gnu)
  (parameter "c" (authorise)))    ; -c VAL is a sub-command, recurse into it
```

The body declares parser-scoped flags and parameters:

| Form                           | Meaning                                                                                                   |
| :----------------------------- | :-------------------------------------------------------------------------------------------------------- |
| `(flag NAME)`                  | `NAME` is a pure boolean flag — it never takes a value.                                                   |
| `(flag NAME (count #v))`       | Boolean flag whose occurrence count binds to `#v` (a count). Models `-vvv`.                               |
| `(parameter NAME)`             | `NAME` is value-bearing. The tokeniser groups `-NAME VAL` so rules see them paired.                       |
| `(parameter NAME #v)`          | As above, binding the value to `#v`. If the flag repeats, `#v` is the last occurrence's value.            |
| `(parameter NAME (one #v))`    | Single value, bound to `#v`. The explicit spelling of `(parameter NAME #v)`.                               |
| `(parameter NAME (last #v))`   | The value of the last occurrence — signals the flag is expected to repeat, last-wins.                     |
| `(parameter NAME (set #v))`    | The list of every occurrence's value, in order. Models `ssh -o`, `docker -e`, `curl -H`.                  |
| `(parameter NAME (command #v))`| A single value that is itself a command line (e.g. `bash -c`). Pair with `(authorise #v)`.                |
| `(parameter NAME (authorise))` | Re-evaluate the captured value as a command line on every invocation (`:via` is recorded).                |

`NAME` follows the same rules as `(flag …)` in rules — a string (`"n"` short,
`"namespace"` long) or a `[short long]` vector.

Each `(parameter …)` takes at most one of the forms above. The plain
`(parameter NAME #v)` keeps a single value (last-wins for repeats); reach
for `(set #v)` when a flag accumulates a list you want to inspect with
`(every? …)` / `(some? …)` (see below). A counted flag's `#v` binds to a
count and is always present (zero when the flag is absent).

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
may-i eval --fact :ci 'systemctl restart nginx'         # set a presence fact
may-i eval --fact :env=prod 'systemctl restart nginx'   # set a value fact
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
    - **Parser body**: `(style …)` first, then `(flags …)`, then
      `(flag …)` declarations alphabetised by name, then `(parameter
      …)` declarations alphabetised by name, then `(positional …)`
      in source order, then `(rest …)` last.
    - **`define-arg-style` body**: attribute forms alphabetised by head
      atom (`combined-shorts` < `long-prefix` < … < `separators`).
    - **`(check …)` body**: source order preserved — cases are
      engine-order-independent but human-curated (users group cases
      under section-header comments).
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

## Notes for agents

If you're an agent reading this:

- **Run `may-i check` after every rule edit.** It catches malformed syntax,
  unresolved `(define …)` references, and regressions in `(check …)` cases.
- **Treat the user's rules as authoritative.** On `:ask` or `:deny`, surface the
  reason verbatim and let the user decide.
- **Rule order in the file does not matter.** Every rule whose command
  matches runs, and the strictest decision wins (`deny > ask > allow`).
  Place new rules wherever they read clearly — a defensive `(deny …)` does
  not need to come first.
- **Reach for `(flag …)` and `(parameter …)` first** when matching options. The
  parser-level forms classify tokens correctly across argv shapes, including
  combined short flags like `-rf`.
- **Add a `(parser …)` only when GNU defaults misclassify a tool's argv.** Most
  programs work out of the box.
- **When recursing via `(authorise)`, land the inner rule first.** Then test with
  `may-i eval 'wrapper inner-cmd …'` to confirm both layers fire.

# may-i Reference

`may-i` evaluates shell commands against rules you write to determine whether a
permission prompt is needed.

Rules are written in an S-expression language at `~/.config/may-i/config.lisp`.

You can update your rules as you work without restarting your agents. The more
time you spend gardening your rules, the more work your agents can do without
prompting you.

## Top-level forms

The most important top-level forms are:

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

### Less-common forms

- `(load "FILE")` — Include another config file (path or glob); useful if config
  gets too long.
- `(parser PROG FORMS…)` — Declare how to parse flags, options and positional
  args for programs that don't use the default GNU style. Most commonly needed
  for programs using the single-dashed `-long` convention.
- `(define-arg-style …)` — Define a custom flag and option-passing convention
  for use in parsers.
- `(safe-env-vars NAMES…)` — Declare environment variables that may be safely
  read. By default, only variables whose values are recovered via static
  analysis are allowed.

## Rule syntax

```lisp
(rule COMMAND EFFECT)
```

- `COMMAND` — program name as a string; also allowed: `(or STRING…)`.
- `EFFECT` — arg pattern, combinator, conditional, or terminal.

Each rule takes exactly one body effect. Use combinators for complex logic.

## Effects

### Terminal effects (return a decision)

```lisp
(effect KEYWORD)
(effect KEYWORD REASON)
```

- `KEYWORD` is one of `:allow`, `:ask`, `:deny`.
- `REASON` is shown in traces and permission prompts.

```lisp
(effect :allow)
(effect :ask "Unsafe operation requires approval")
```

### Arg patterns (return Allow on match, Nil otherwise)

| Form                    | Meaning                                                                       |
| :---------------------- | :---------------------------------------------------------------------------- |
| `(flag NAME)`           | A flag, as in `-r`.                                                           |
| `(parameter NAME FORM)` | A flag with an argument, as in `--file ./foo`; consumes the associated value. |
| `(positional PAT…)`     | Ordered sequence of args that were not consumed as flags or parameters.       |
| `(exact PAT…)`          | A strict positional; fails if any positional args are left unconsumed.        |

Less common, but sometimes useful:

| Form               | Meaning                              |
| :----------------- | :----------------------------------- |
| `(anywhere PAT…)`  | Token appears anywhere in argv.      |
| `(forbidden PAT…)` | None of these tokens appear in argv. |

### Flag and parameter names

`flag` and `parameter` names are given as strings or vectors of equivalents:

| Spelling        | Meaning                                                              |
| :-------------- | :------------------------------------------------------------------- |
| `"x"`           | Short flags, as in `-x` or `-fx`. Assumed composable in most styles. |
| `"force"`       | Long flags, as in `--force`.                                         |
| `["f" "force"]` | Alternatives, as in `-f` or `--force`.                               |

`(parameter NAME FORM)` consumes the flag and its associated value. `FORM` is
one of:

| Form          | Meaning                                               |
| :------------ | :---------------------------------------------------- |
| `(may-i *)`   | Parse the value as a command line and recurse.        |
| `(regex "…")` | Regex match the value as a single token.              |
| `"literal"`   | Exact value match.                                    |
| `*`           | Match any value (parameter is just a presence check). |

#### Examples

```lisp
(rule "rm"   (and (not (flag "r"))   (effect :allow)))
(rule "git"  (and (positional "push") (not (flag ["f" "force"])) (effect :allow)))
(rule "curl" (and (parameter ["X" "request"] "POST") (effect :allow)))
(rule "bash" (parameter "c" (may-i *)))     ; recurse into bash -c VAL
```

### Expression patterns (match a single token)

| Form          | Meaning                      |
| :------------ | :--------------------------- |
| `"string"`    | Literal match.               |
| `*`           | Wildcard (matches anything). |
| `(regex "…")` | Regex match.                 |
| `(or PAT…)`   | Match any.                   |
| `(and PAT…)`  | Match all.                   |
| `(not PAT)`   | Negate.                      |
| `[:key *]`    | Bind matched value as fact.  |

### Quantifiers (wrap a positional pattern)

| Form       | Meaning                |
| :--------- | :--------------------- |
| `EXPR`     | Exactly one (default). |
| `(? EXPR)` | Zero or one.           |
| `(+ EXPR)` | One or more.           |
| `(* EXPR)` | Zero or more.          |

### Combinators

| Form            | Meaning                                   |
| :-------------- | :---------------------------------------- |
| `(and EFFECT…)` | All must succeed (short-circuits on Nil). |
| `(or EFFECT…)`  | First non-Nil wins.                       |
| `(not EFFECT)`  | Swap Allow ↔ Nil; pass Ask/Deny through.  |

### Conditionals (predicate controls branching)

| Form                              | Meaning                            |
| :-------------------------------- | :--------------------------------- |
| `(when PRED EFFECT)`              | Effect if predicate matches.       |
| `(unless PRED EFFECT)`            | Effect if predicate doesn't match. |
| `(if PRED THEN ELSE)`             | If-then-else.                      |
| `(cond ((PRED EFF)…) (else EFF))` | Multi-way branch.                  |

Predicates: `(fact? …)`, arg patterns, named refs, `(and/or/not …)`.

### Recursive evaluation

```lisp
(positional . (may-i *))              ; Eval rest as command (sudo)
(positional [:host *] . (may-i *))    ; Bind host, eval rest (ssh)
```

`(may-i *)` automatically adds the wrapper command name to the `:via` fact set.
For example, `(rule "sudo" (positional . (may-i *)))` sets `:via` to `"sudo"`.
Query with `(fact? [:via "sudo"])`.

## Facts

Facts provide runtime context via `--fact` or automatic binding (see may-i
recursion above).

Two forms:

| Shape           | Meaning                 |
| :-------------- | :---------------------- |
| `:ci`           | Presence — key exists.  |
| `[:env "prod"]` | Value — key with value. |

Query with `(fact? …)`:

```lisp
(fact? :ci)                          ; presence check
(fact? [:env "prod"])                ; exact value
(fact? [:host (regex "^prod-")])     ; regex match
(and (fact? A) (fact? B))            ; combined
```

Pass facts to eval:

```bash
may-i eval --fact :ci --fact :env=prod 'kubectl get pods'
```

## Named predicates

Define reusable predicates:

```lisp
(define prod-host
  (fact? [:ssh/host (regex "^prod-")]))
```

Use in rules:

```lisp
(rule "kubectl"
  (if prod-host
      (effect :deny "No prod access")
    (effect :allow)))
```

## Checks

Write tests at top-level or inside rules:

```lisp
(check :allow "ls -la"
       :deny "rm -rf /")
```

With facts:

```lisp
(check (with-facts [[:env "prod"]]
         :deny "kubectl get pods")
       (with-facts [[:env "dev"]]
         :allow "kubectl get pods"))
```

Validate with `may-i check`.

## Load

Split config across files:

```lisp
(load "rules/git.lisp")              ; Load a file (relative to config dir)
(load "rules/*.lisp")                ; Glob pattern, loaded in lexical order
```

Paths resolve relative to the file containing the load form. Recursive loads are
supported. Circular loads are detected and rejected.

## Safe env vars

Whitelist environment variables for shell expansion:

```lisp
(safe-env-vars "HOME" "PWD" "USER" "SHELL" "EDITOR")
```

## Tokenisation

Each program's argv is split into flags, flag values, and positional arguments
under a parsing _style_. Styles are first-class data, declared via
`(define-arg-style …)`. The prelude ships four:

| Style              | Behaviour                                                                                                                        |
| :----------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| `gnu`              | Short `-x`, long `--foo`, combine `-rf` → `-r -f`, `--foo=val` or `--foo val`. The default when no `(parser …)` is declared.     |
| `single-dash-long` | Every `-foo` is a single long flag; no combining. Used by tools like `find`, `go`, `terraform`, `java`.                          |
| `legacy-bundle`    | First non-dashed alpha-cluster is a flag bundle (e.g. `tar xvzf` → `-x -v -z -f`); subsequent tokens follow `gnu` rules.         |
| `key-value`        | `key=value` tokens are flag-equivalent; everything else is positional. `:pun :error` rejects bare keys. Used by tools like `dd`. |

### `(define-arg-style …)`

Bind a parsing style to a name so one or more `(parser …)` forms can reference
it. A style describes _how_ a program spells its flags (prefixes, separators,
combining rules) — not _which_ flags it has.

```lisp
(define-arg-style NAME (KEY VALUE …))
```

Recognised PLIST keys:

| Key                   | Type    | Default  | Meaning                                                                                                           |
| :-------------------- | :------ | :------- | :---------------------------------------------------------------------------------------------------------------- |
| `:long-prefix`        | string  | `"--"`   | Long-flag prefix.                                                                                                 |
| `:short-prefix`       | string  | `"-"`    | Short-flag prefix.                                                                                                |
| `:separators`         | (str…)  | `(" ")`  | Separators between parameter and value.                                                                           |
| `:combined-shorts`    | bool    | `nil`    | `-rf` → `-r -f`.                                                                                                  |
| `:first-token-bundle` | bool    | `nil`    | First non-dashed cluster is a flag bundle.                                                                        |
| `:pun`                | keyword | `:allow` | `:allow` ⇒ bare parameter is value-less; `:error` ⇒ bare parameter is a tokenisation error.                       |
| `:overrides`          | symbol  | _none_   | Derive from another style, replacing only the keys listed in this PLIST. List-valued keys _replace_, don't merge. |

Cycles in `:overrides` and unknown keys are config-load errors.

```lisp
(define-arg-style java
  (:overrides gnu :separators (" " "=" ":")))
```

### `(parser …)`

Tell the tokeniser how a specific program's argv works: which style governs flag
spelling, which flags carry values (so `-X VAL` groups), and which carry a
command line to re-authorise. Rules then see a correctly-partitioned
positional/flag stream.

```lisp
(parser PROGRAM :style STYLE BODY…)
```

Body items:

| Form                         | Meaning                                                                                                                          |
| :--------------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| `(flag NAME)`                | Declare `NAME` as a pure boolean flag.                                                                                           |
| `(parameter NAME)`           | Declare `NAME` as a value-bearing parameter. The tokeniser groups `-N VAL` correctly.                                            |
| `(parameter NAME (may-i *))` | Additionally re-authorise the captured value as a command line on every invocation. Recursion result is recorded as `:via NAME`. |

`NAME` is a string (length 1 ⇒ short, longer ⇒ long) or a vector `[short long]`
of two strings.

Default fallback: programs without a `(parser …)` use the `gnu` style with no
parameter declarations.

```lisp
(parser "find"    :style single-dash-long)
(parser "tar"     :style legacy-bundle)
(parser "dd"      :style key-value
  (parameter "if") (parameter "of") (parameter "bs"))
(parser "kubectl" :style gnu (parameter ["n" "namespace"]))
(parser "bash"    :style gnu (parameter "c" (may-i *)))
```

The trace surfaces the resolved style and parameter declarations per evaluation.

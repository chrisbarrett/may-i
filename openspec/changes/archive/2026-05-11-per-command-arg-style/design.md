## Context

`crates/engine/src/eval/entry.rs` currently defines two profile-aware
functions (`expand_combined_flags(args, &Convention)`,
`positional_args(args, &Convention)`) that drive tokenisation. They were
introduced by the first draft of this change as an `(args-style PROGRAM
:PROFILE …)` declaration with four hard-coded profile keywords.

That design conflates two concerns:

1. **How flags are spelled** for this program — long-prefix, short-prefix,
   combined-shorts, separator characters between parameter and value.
2. **Which options on this program take values** — and what to do with
   those values (e.g. always re-authorise `bash -c VAL`).

Conflating them means every new tool family forces either a new profile
keyword or a one-off override. There is also no hook for declarative
per-program semantic facts beyond "this token consumes the next one".

This change separates the two concerns. **Style** is reusable data,
declared once via `(define …)`, capturing concern (1). **Parser** is a
per-program declaration that selects a style and adds parser-scoped
`(flag …)` / `(parameter …)` forms covering concern (2).

Top-level config forms today: `Rule`, `Define`, `Check`, `SecurityConfig`,
`SafeEnvVars`, `Load`. Adding `Parser` is well-trodden. `Define` already
exists for fact bindings; this change extends `Define`'s body grammar to
accept a style PLIST.

## Goals / Non-Goals

**Goals:**

- Style is data. Anything the prelude can express, a user can express via
  their own `(define …)`. The prelude has no special powers.
- A single `(parser PROGRAM :style STYLE BODY…)` declaration per command
  is the only place argv shape is configured.
- Parser-level `(parameter X (may-i *))` declares always-on
  re-authorisation of a parameter's value. No corresponding rule needed.
- Default fallback: programs with no `(parser …)` use the `gnu` style
  with no parameter declarations. Existing rule-only configs continue to
  work for tools that match GNU conventions.
- The `(may-i …)` recursion path picks up the inner command's parser
  automatically (lookup by `ctx.command`).

**Non-Goals:**

- Per-subcommand parsers (`git rebase` vs `git push`). Subcommands are
  unbounded for tools like `git`; the right tool here is parser-level
  `(parameter …)` declarations that cover the cross-cutting options
  (`-c`, `-C`, etc.). If a specific subcommand truly behaves like its own
  program, the user can add a separate `(parser "git rebase" …)` later
  (out of scope for this change).
- Inferring styles by parsing tool help text — magical, fragile.
- Type-checked parameter values (e.g. `(parameter "n" :as integer …)`) —
  reserved as a future expansion of the parser-level FORM slot.

## Decisions

### 1. `define` is the only way to bind a style

```lisp
(define gnu
  (:long-prefix "--" :short-prefix "-"
   :separators (" " "=")
   :combined-shorts t
   :pun :allow))
```

Styles are property lists. The prelude is loaded as if the user had
written it, including its `(define …)` forms. Users can re-bind a name
(last `define` wins, with a warning), and can derive new styles from
existing ones.

**Alternative**: keyword-only profiles (`:gnu`, `:single-dash-long`, …).
Rejected — keeps the system closed; new tool families need a code change.

### 2. Style derivation via `:overrides`

```lisp
(define legacy-bundle
  (:overrides gnu :first-token-bundle t))

(define java
  (:overrides gnu :separators (" " "=" ":")))
```

`:overrides BASE` is resolved at style-resolution time. Keys present in
the deriving PLIST replace the same keys in `BASE`. **List-valued keys
replace, they do not merge** — `:separators` in `java` above is exactly
`(" " "=" ":")`, not `(" " "=" " " "=" ":")`. Predictability over
convenience.

Cycles in `:overrides` are a config-load error.

### 3. Style PLIST keys (initial set)

| Key                     | Type      | Default | Meaning                                        |
| :---------------------- | :-------- | :------ | :--------------------------------------------- |
| `:long-prefix`          | string    | `"--"`  | Prefix for long flags                          |
| `:short-prefix`         | string    | `"-"`   | Prefix for short flags                         |
| `:separators`           | list-str  | `(" ")` | Allowed separators between parameter and value |
| `:combined-shorts`      | bool      | `nil`   | Whether `-rf` expands to `-r -f`               |
| `:first-token-bundle`   | bool      | `nil`   | Whether first non-dashed alpha cluster is flag bundle |
| `:pun`                  | keyword   | `:allow`| `:allow` ⇒ bare parameter occurrence is value-less; `:error` ⇒ tokenisation error |
| `:overrides`            | symbol    | absent  | Inherit from named style                       |

Unknown keys are a config-load error to keep typos from silently
disabling features. Future keys are added by extending this table; the
parser MUST reject keys it does not recognise.

### 4. Prelude styles

Shipped as auto-loaded source:

```lisp
(define gnu
  (:long-prefix "--" :short-prefix "-"
   :separators (" " "=")
   :combined-shorts t
   :pun :allow))

(define single-dash-long
  (:long-prefix "-" :short-prefix "-"
   :separators (" " "=")
   :combined-shorts nil
   :pun :allow))

(define legacy-bundle
  (:overrides gnu :first-token-bundle t))

(define key-value
  (:long-prefix "" :short-prefix ""
   :separators ("=")
   :combined-shorts nil
   :pun :error))
```

These are bound at `Config` construction time so user `(define …)` forms
can `:overrides` them or shadow them.

### 5. `(parser PROGRAM :style STYLE BODY…)`

```lisp
(parser "git"
  :style gnu
  (parameter ["c" "command"] (may-i *))
  (parameter ["C" "directory"]))

(parser "tar"     :style legacy-bundle)
(parser "find"    :style single-dash-long)
(parser "dd"      :style key-value)
```

`BODY` accepts:

- `(flag NAME)` — boolean flag declaration. `NAME` is a string or
  `[short long]` vector. Equivalent to "this is a flag, not a parameter,
  and never takes a value".
- `(parameter NAME [FORM])` — value-bearing parameter. `NAME` is a string
  or `[short long]` vector. Optional `FORM`:
  - omitted ⇒ register as value-bearing only.
  - `(may-i *)` ⇒ at evaluation time, parse the captured value as a
    command line and re-authorise via the standard `(may-i …)` recursion
    path. The decision flows back into the trace as a virtual `Effect`
    event keyed to this parser declaration.
  - other expressions ⇒ rejected at parse time in v1; reserved for
    future use (`:as integer`, regex restriction, …).

When the same parameter name is declared twice in one parser body, last
wins with a warning.

### 6. Match semantics in rules

Unchanged from the `flag-and-parameter-patterns` design, with one
clarification under `:pun :allow`:

| Rule form                  | Bare `--enable`                 | `--enable=true`           | absent |
| :------------------------- | :------------------------------ | :------------------------ | :----- |
| `(flag "enable")`          | match (Allow)                   | match (Allow)             | Nil    |
| `(parameter "enable" *)`   | Nil (no value present)          | match (Allow)             | Nil    |
| `(parameter "enable" "true")` | Nil                          | match (Allow)             | Nil    |

Under `:pun :error` the bare-`--enable` case is rejected at tokenisation;
no rule sees it.

### 7. Parser-level `(parameter X (may-i *))` — always-on recursion

When the tokeniser, working under `parser P`, finds a value for parameter
`X` declared with `(may-i *)`, it triggers a recursive `evaluate` on the
captured value before any rule for `P` runs. The result of that recursion
*does not* short-circuit `P`'s rule evaluation — it is recorded in the
context (as a fact `:via X`) and surfaced in traces. A subsequent rule
can pick it up via `(when (= :via "command") …)` or similar; in practice,
most users will rely on the rule-level `(may-i …)` instead.

Rationale: keeps the parser layer purely about *parsing* (what's a
flag/value/positional?). The rule layer remains the only place
*authorisation decisions* are made. The parser just guarantees that the
right things have been parsed and recursively classified.

**Alternative**: have parser-level `(parameter X (may-i *))` short-circuit
the parent rule's decision to the recursion's result. Rejected — too
much spooky action at a distance; users would be surprised when their
rule body never runs.

### 8. Default fallback and migration

- Programs with no `(parser …)` use the `gnu` style and have no parameter
  declarations. This preserves existing behaviour for the majority of
  configs.
- The existing `(args-style …)` form is removed at config-parse time.
  Configs in the repo that use it are migrated as part of this change.
- A `may-i migrate` rewrite converts `(args-style PROGRAM :PROFILE [...])`
  into the equivalent `(parser PROGRAM :style STYLE)` plus zero or more
  parameter declarations corresponding to `:flags-with-values`.

### 9. Tokeniser shape

```rust
struct Style {
    name: SymbolName,
    long_prefix: String,
    short_prefix: String,
    separators: Vec<String>,
    combined_shorts: bool,
    first_token_bundle: bool,
    pun: PunPolicy,
}

struct ParameterDecl {
    names: Vec<String>,                    // short/long spellings
    treatment: ParameterTreatment,         // None | MayI | (future)
}

struct Parser {
    program: String,
    style: Style,                          // resolved (overrides applied)
    flags: Vec<Vec<String>>,               // (flag …) declarations
    parameters: Vec<ParameterDecl>,
}

fn tokenise(args: &[String], parser: &Parser) -> AnnotatedStream;
```

`AnnotatedStream` is the existing annotated-token type; the new
`tokenise` returns it directly rather than going through two passes
(`expand_combined_flags` then `positional_args`).

### 10. Trace output

Trace shows the resolved parser once per evaluation: program, style
name, list of flags, list of parameters with treatment. Helps users
debug "why didn't `-n` get treated as value-bearing?".

For parser-level `(parameter X (may-i *))` recursion, the trace nests
the inner evaluation under the parser declaration, mirroring the
existing `(may-i …)` rule-level rendering.

## Risks / Trade-offs

- **Breaking change to in-tree code.** `(args-style …)` already shipped
  in this branch. The pivot removes it before the branch merges; nothing
  external depends on it yet.
- **Larger config surface.** Two new top-level forms (`define` body
  extended; `parser`) instead of one (`args-style`). Mitigated by
  per-program `(parser …)` being optional and by the prelude covering the
  common cases.
- **Style indirection.** A user reading `(parser "find" :style
  single-dash-long)` has to know what `single-dash-long` means. Mitigate:
  trace shows the resolved style PLIST inline; `may-i reference` lists
  prelude styles.
- **Always-on recursion is a behaviour change.** Under
  `(parameter X (may-i *))`, every invocation triggers a recursive
  `evaluate`. Cost is bounded by the existing recursion limit; trace
  shows the recursion clearly. Users opt in by declaring it.
- **Pun policy choice may surprise.** Under `gnu`'s `:pun :allow`, bare
  `--enable` is value-less and `(parameter "enable" *)` returns Nil.
  Users expecting "value or empty string" will need to write
  `(or (parameter "enable" *) (flag "enable"))`. Document with examples.

## Open Questions

- **Should `:separators` accept regex/character classes?** Default
  string-list is enough for v1. Add later if a real tool needs it.
- **Should parameter declarations support a default value?** Out of scope
  — rule-level `(or (parameter X *) "default")` covers it.
- **Where does `(parser …)` live in the load order vs `(rule …)` and
  `(define …)`?** Parsers must be resolvable before rules tokenise their
  args. Two options: (a) require parsers to load before any rule that
  evaluates the same program; (b) two-pass config load: collect all
  parsers and styles first, then resolve rules. Lean: (b) — one less
  thing for users to think about.
- **Multiple parsers for the same program.** Last-wins with a warning,
  matching the rest of the system. Could be an error; lean for
  consistency.

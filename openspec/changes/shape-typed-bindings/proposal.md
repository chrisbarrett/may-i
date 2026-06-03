## Why

Today's `#var` binding system is shape-agnostic: a parser declaration like
`(parameter "o" #opts)` produces an opaquely-typed binding. Rule bodies can
ask whether a binding is present (`(bound? …)`), match it as a single token
or joined string (`(matches? …)`), or recurse on it (`(authorise …)`) —
but there is no way to express "this parameter appears multiple times and
all of its values must satisfy P," nor any way for the engine to catch the
inevitable mistakes (e.g. asking `(authorise …)` on a collection-shaped
binding, or asking a quantifier over a single-string binding).

The triggering case is a multi-positional `rm` rule: the user wants to
allow `rm -rf` only when **every** positional satisfies a safe-path
predicate. Current shapes (`(exact PAT…)`, `(or …)`, the `?`/`*`/`+`
quantifiers inside `(positional …)`) cover it for positionals by accident
of expression — but the same need arises for repeated parameters like
`ssh -o A=1 -o B=2` and `docker -e X -e Y`, and there is no clean spelling
there.

The deeper issue is that `#var` is a binding-system-in-waiting without a
type discipline. Adding the quantifier surface (`every?` / `some?`) without
shapes ships a footgun; adding shapes without the quantifier ships dead
weight. Bundle them.

## What Changes

- **Parser side: shape-bearing binding declarations.** Extend
  `(parameter NAME …)`, `(positional …)`, and `(rest …)` so the binding
  declaration names a *shape*:
  - `(parameter NAME (one  #v))` — single-occurrence; binding is a single
    token. Default when no shape form is given (preserves today's
    semantics).
  - `(parameter NAME (last #v))` — multi-occurrence; binding is the *last*
    occurrence's value. Models last-wins programs (gcc `-O`, many
    `--config` parameters).
  - `(parameter NAME (set  #v))` — multi-occurrence; binding is the
    collection of all values, in source order. Models set-accumulating
    programs (ssh `-o`, docker `-e`, curl `-H`).
  - `(parameter NAME (many-till PAT) #v)` — multi-token capture (existing
    form); binding shape is `Collection Token`.
  - `(positional #v *|+)` — multi-positional capture (existing form);
    binding shape is `Collection Token`.
  - `(flag NAME (count #v))` — countable-flag occurrences; binding shape
    is `Count` (non-negative integer). Models `-vvv` style.
- **Rule side: quantifier verbs over collection-shaped bindings.**
  - `(every? #v PRED)` — true iff `PRED` matches every element of the
    collection bound to `#v`. Empty collection ⇒ true (vacuous).
  - `(some? #v PRED)` — true iff `PRED` matches at least one element of
    the collection bound to `#v`. Empty collection ⇒ false.
  - Both fold a single-token predicate (literal, regex, `(or …)`, `(and
    …)`, `(not …)`, `*`, `[:k *]`) over the collection's tokens.
- **Shape system: types and diagnostics.** Introduce a small type
  vocabulary — `Token`, `Command`, `Collection τ`, `Count` — used
  internally to check rule bodies against the bindings their parsers
  declare. Mismatches surface at config-load time and through
  `may-i check`, with messages naming the actual and expected shape. The
  user-facing vocabulary stays "binding" / "value" / "collection"; the
  word _shape_ is contributor-facing.
- **Canonical form / trust hashing.** The binding-shape declarations
  participate in the canonical-form signature. Migrating
  `(parameter "o" #v)` → `(parameter "o" (set #v))` is a Class B change
  (semantics shift): trust state does not auto-carry.
- **Existing single-occurrence semantics preserved.** Today's
  `(parameter NAME #v)` (no shape form) keeps binding to the last
  occurrence's value as a single token — same as `(last #v)` — so existing
  rules and prelude declarations are unaffected. The shape system is
  *added*; no rules break.
- **The `rm` motivating case becomes:**
  ```lisp
  (rule "rm"
    (when (flag ["r" "recursive"])
      (cond
        ((anywhere "/")               (deny "Recursive deletion from root"))
        ((every? #positionals safe?)  (allow "Tmp/cache paths only"))
        (else                         (ask  "Recursive deletion")))))
  ```
  with `safe?` a `(define …)`d alternation and `#positionals` declared
  parser-side as a collection-shaped positional binding.

## Capabilities

### New Capabilities

- `binding-shapes`: the contributor-facing type system. Defines the shape
  vocabulary (`Token`, `Command`, `Collection τ`, `Count`), shape inference
  over parser declarations, shape checking against rule-body uses, the
  diagnostic surface for mismatches, and the canonical-form contribution
  of shape declarations. Bucket: `contributor-internals`.

### Modified Capabilities

- `parser-bindings`: add the shape-bearing declaration forms (`(one #v)`,
  `(last #v)`, `(set #v)`, `(count #v)`) and the multi-occurrence
  semantics they imply; clarify that today's unannotated
  `(parameter NAME #v)` is sugar for `(last #v)` to preserve existing
  semantics.
- `patterns`: add the rule-body quantifier forms `(every? #v PRED)` and
  `(some? #v PRED)`. Specify the empty-collection truth values, the
  predicate sublanguage they accept, and their fold order.

## Impact

- **Surface DSL.** New shape forms and quantifier verbs. Additive; no
  existing rule shape is invalidated.
- **Engine.** Multi-occurrence parameter handling becomes shape-driven
  rather than fixed last-wins. New evaluator paths for `every?` / `some?`
  fold. New shape-checking pass during config load.
- **Prelude.** No semantic changes required — every existing prelude
  parser declares `(parameter NAME)` or `(parameter NAME #v)` with last-
  wins semantics, which the new system preserves. Future prelude updates
  can opt particular parameters into `(set …)` (e.g. ssh `-o`) on a
  case-by-case basis.
- **Trust hashing.** Shape declarations enter the canonical form. Trust
  entries hashed under the pre-change form continue to verify (the
  unannotated `(parameter NAME #v)` form's canonicalisation is unchanged);
  opting an existing parameter into a new shape is a Class B change.
- **Migration.** No automatic rewrites required. The migration system
  gains awareness of the new declaration kinds so `may-i migrate` does
  not flag them as unknown.
- **`may-i check`.** Gains shape-mismatch diagnostics; existing checks
  unaffected.
- **CLI.** No new subcommands. Error rendering grows shape-mismatch
  variants.
- **Dependencies.** None new expected; the type system is small enough to
  implement inline.

## Context

`crates/core/src/ast.rs` defines `ArgPattern` with variants `Ordered`
(positional/exact), `Anywhere`, and `Forbidden`. None of them express
flag-aware semantics — they all match against literal token text. Combined
with the GNU-only tokeniser, this leaves users encoding flag concerns
through brittle string matches.

`per-command-arg-style` adds the profile machinery so the tokeniser can
produce annotated tokens (flags vs values vs positionals). This change
adds the rule-side patterns that consume those annotations.

## Goals / Non-Goals

**Goals:**
- A single, consistent way to express "this flag is present" and "this
  flag's value satisfies …" across short and long forms.
- The new forms compose with all existing combinators (`and`, `or`, `not`,
  `cond`).
- Old configs migrate automatically via the existing rewrite-rule
  registry.
- The `(positional "-c" . (may-i *))` problem becomes a non-issue —
  `(parameter "c" (may-i *))` is the canonical form.

**Non-Goals:**
- Per-flag value-type validation (e.g. `(parameter "n" :as integer …)`).
  Out of scope; users can use `(regex …)` for now.
- Position-sensitive flag matching ("`-v` only counts before `--`"). The
  tokeniser already handles `--` as a terminator; flags after `--` are
  positional and not visible to `(flag …)`.
- Argument grouping / capture into facts beyond the existing fact-bind
  expressions, which already work as `FORM` in `(parameter X FORM)`.

## Decisions

### 1. Length-based short/long distinction

```
   (flag "x")       length 1 ⇒ short  (matches -x, including in -rfx)
   (flag "force")   length >1 ⇒ long  (matches --force or -force per profile)
   (flag ["x" "force"])              short OR long
```

Single-character names always denote short flags. Multi-character names
always denote long flags. No need for `:short` / `:long` keyword tags
unless an exotic case appears.

**Alternative**: explicit tags (`(flag :short "x")`). Rejected — verbose
for the common case. Add later if exotic tools require it.

### 2. Flag character set is determined by the shell parser

The shell parser produces tokens like `--feature-x`, `--feature_x`,
`--UPPER` already. `(flag …)` does not attempt to validate or restrict
flag spellings — it inspects the parser's output. Whatever the shell
tokenises as a flag-shaped word is matchable.

### 3. Negation through `(not …)`

```
   (not (flag "force"))         ; --force absent
   (not (parameter "X" "POST")) ; -X is absent or its value is not "POST"
```

No dedicated `(no-flag …)` form. Existing `(not …)` is sufficient.

### 4. `(parameter …)` implicitly registers as value-bearing

When evaluating a rule that contains `(parameter "c" FORM)` for command
`bash`, the tokeniser treats `-c` as a value-bearing flag for that
evaluation, even if `args-style "bash"` does not list it under
`:flags-with-values`. This avoids requiring users to declare the same
flag twice.

Implementation: before tokenising, the evaluator collects the union of
flag names from `(parameter …)` patterns in rules that target the current
command. Pass that set as an additional `flags_with_values` to the
tokeniser.

### 5. Consumption rules

```
   (parameter "c" FORM)
       ↳ consumes both -c and its value from the visible stream
         used by sibling (positional …) / (anywhere …) patterns
         in the same rule.
   
   (flag "v")
       ↳ does NOT consume. Boolean check only — sibling matchers
         see the same stream.
```

Rationale: positional matching needs to ignore tokens already accounted
for by `(parameter …)`. Boolean `(flag …)` is a query, not a binding, so
nothing to consume.

### 6. Match semantics return values

```
   (flag X)              present ⇒ Allow,  absent ⇒ Nil
   (parameter X FORM)    present ⇒ result of FORM against value
                         absent  ⇒ Nil
```

This matches existing `(positional …)` etc. — Nil means "this rule
doesn't apply"; the next rule is tried.

### 7. `=`-attached and space-separated forms both match

```
   --force=true       (flag "force") ⇒ true
   --force            (flag "force") ⇒ true
   -X POST            (parameter ["X" "request"] "POST") ⇒ true
   --request=POST     (parameter ["X" "request"] "POST") ⇒ true
   -XPOST             rsync-style glued; opt-in via override (later)
```

Default forms are `-X VAL`, `-X=VAL`, `--long VAL`, `--long=VAL`. Glued
short-with-value (`-XPOST`) is rare enough to defer.

### 8. Migration shapes

Three rewrites added to the migration pipeline:

```
   (anywhere "-x")         ⇒  (flag "x")
   (anywhere "--foo")      ⇒  (flag "foo")
   (forbidden "-x")        ⇒  (not (flag "x"))
   (forbidden "--foo")     ⇒  (not (flag "foo"))
   (positional "-c" . R)   ⇒  (parameter "c" R)
   (positional "--cmd" . R)⇒  (parameter "cmd" R)
```

Rewrites apply only when the literal starts with `-`. Mixed cases
(`(anywhere "-x" "verb")`) are split.

## Risks / Trade-offs

- **Subtle behaviour shift on migration.** `(anywhere "-x")` matches *any
  occurrence* of the literal token `-x`, including positional-after-`--`
  (`echo -x`). `(flag "x")` only matches flag-classified tokens. In
  practice this is the desired tightening, but it's a behaviour change.
  Mitigate: migration emits a one-time note per rewritten rule; trace
  surfaces the new semantics.
- **Implicit value-bearing registration is per-rule.** If two rules
  exist for the same command and only one declares `(parameter "c" …)`,
  the OTHER rule's tokenisation could differ. Mitigate: implicit
  registration is global per command (union across all rules for that
  command), so all rules see the same tokenisation. Document clearly.
- **Confusion with `(args-style :flags-with-values)`.** Two ways to
  declare the same thing. Mitigate: trace shows the merged effective
  list; `args-style` is for "I want this tokenised correctly even though
  no rule references it"; `(parameter …)` is for "I'm using the value".

## Open Questions

- Should `(flag ["s" "long"])` accept more than two alternatives
  (`(flag ["v" "verbose" "vv"])`)? Probably not — most flags don't have
  three forms. Use `(or (flag "v") (flag "verbose"))` for unusual cases.
- Should `(parameter X *)` (wildcard form) be a synonym for `(flag X)`?
  Currently no — different consumption semantics matter. Keep distinct.
- Vector vs `(or …)` syntax: `[short long]` is concise but introduces a
  new shape. Could be `(flag (or "s" "long"))` for consistency. Decide at
  implementation time.

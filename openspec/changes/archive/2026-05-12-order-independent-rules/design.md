## Context

Two systems currently disagree about whether rule order is semantically
significant:

- The engine (`crates/engine/src/eval/entry.rs::Evaluator::evaluate`) walks
  rules top-to-bottom and `return`s on the first non-Nil result. Order is
  semantically significant. A `(rule "rm" (effect :allow))` placed before a
  `(rule "rm" (when (flag "r") (effect :deny)))` makes the deny unreachable.
- The trust-hashing spec captures this by hashing the *ordered* closure:
  reordering rules changes the hash, even when the meaning of the config is
  arguably unchanged. This is a defensive admission that order matters.

The user-level mental model — and the one we want to ship — is the opposite:
the program name selects an unordered set of rules; every applicable rule is
evaluated; the strictest decision wins. Composition becomes predictable,
because importing a `(load …)` file cannot reach back and change the meaning
of an earlier rule. Trust review can confirm the rule *content* without also
worrying about layout.

The same "strictest wins" aggregation already exists in `evaluate_command` for
compound shell commands (`cmd1 && cmd2`, embedded substitutions). We are
extending the model down one level so the per-program rule list works the
same way.

## Goals / Non-Goals

**Goals:**

- Specify rule evaluation as: program name → applicable set → strictest
  non-Nil decision.
- Make the order-independence guarantee testable by property tests
  (shuffling rules within a config produces identical decisions).
- Update trust hashing so reorderings, comment edits, and `(load …)` file
  splits do not change the hash.
- Preserve the existing compound-command aggregation in `evaluate_command`;
  the new per-program model composes cleanly with it.

**Non-Goals:**

- Changing the surface DSL. `(rule …)`, `(define …)`, `(parser …)` are
  unchanged.
- Removing combinators. Within a single rule body, `(and …)`, `(or …)`,
  `(when …)`, `(if …)`, `(cond …)` keep their current semantics — the
  short-circuit happens *inside* a rule body, not across rules.
- Changing how `(check …)` validates. Each `(check …)` line still asserts the
  decision for one command; that decision is now the strictest-wins outcome,
  which is what users already expect when reading their config.

## Decisions

### 1. All applicable rules run; strictest wins

```
applicable = [r for r in config.rules if r.command_effect.matches(ctx.command)]
results    = [evaluate_rule(r, ctx) for r in applicable]
nonNil     = [r for r in results if r is not Nil]
decision   = max(nonNil, key=strictness) if nonNil else default_ask
```

`strictness` is `Deny > Ask > Allow` — the same ordering used in
`evaluate_command_inner`'s `result.decision >= aggregate_decision` test.

When two rules return the same strictness (e.g. two Denies), the reason
field is taken from one deterministically. Lean: *concatenate distinct
reasons with `; `*, so the user sees every dissenting rule. Alternative:
take the lexically-first reason. Concatenation surfaces more information
without ordering surprises; trace already shows each rule individually.

### 2. Tie-breaking is order-free

The reason-aggregation rule above must itself be order-free. Sort distinct
reasons lexically before joining. This means
`(rule "rm" (effect :deny "A")) (rule "rm" (effect :deny "B"))` and the
reverse produce the same final reason, `"A; B"`.

### 3. Default-Ask threshold is preserved

If no applicable rule returns a non-Nil result, the engine still emits
`Decision::Ask` with the existing
"`Rules for X exist but…`" / "`No rule for command X`" reason. The reason
selection between the two messages is a function of *whether any rule's
command pattern matched*, which is order-free.

### 4. Compound-command aggregation is unchanged

`evaluate_command_inner` already does
`aggregate_decision = max(aggregate_decision, segment.decision)`. The
per-program engine now uses the same logic, one layer in. Net effect:

```
final = max(strictness)
          over all segments S of the input shell command
            over all rules R applicable to S.command
              evaluate_rule(R, …)
```

This is straightforward to reason about and matches the user's mental
model.

### 5. Trust hash is computed over a canonical set

Today's hash:

```
sha256( serialize_in_source_order( applicable_rules + referenced_defines ) )
```

New hash:

```
sha256( "\n".join( sorted( serialize(r) for r in applicable_rules ) )
      + "\n--\n"
      + "\n".join( sorted( serialize(d) for d in referenced_defines ) ) )
```

`serialize` is the existing canonical s-expression renderer used for
hashing — comments and whitespace are already excluded. The change is
that we sort the resulting strings before joining, so two configs that
differ only in rule ordering hash identically.

The split between rules and defines (with the `--` separator) keeps the
two namespaces independent: a rule named `rm` and a define named `rm` do
not collide.

### 6. (Out of scope, but called out) Re-defining a name

If two `(rule …)` declarations in the same config target the same program
and both produce decisions for the same input, both contribute to the
strictest-wins aggregation. There is no longer a "last definition wins"
fallback for rules, and there never really was one — the previous
semantics were "first match wins", which is also surprising. With the new
model, users who intend "override" must express it explicitly via
combinators or `(when …)` predicates.

`(define …)` re-binding semantics are unchanged: the last `(define …)`
for a given name still wins, with a warning. (Defines are name → body
bindings, not rule bodies; their resolution is one-to-one and order in
the source IS the disambiguator. Treating them as a set would force us
to error on duplicates, which is harsher than today.)

## Risks / Trade-offs

- **Existing configs that relied on first-match ordering will change
  behaviour.** → Migration risk. Mitigation: in-tree configs are audited as
  part of this change. The `starter_config.lisp` does not depend on
  first-match (rule bodies use `(cond …)` for branching). For external users:
  the `may-i check` test suite catches divergences before deployment.

- **Trust hashes for existing `Loaded`-rule configs will change once.** →
  Users will be re-prompted to trust their loaded configs the first time
  they run after the upgrade. Acceptable for a pre-1.0 cut. Document in
  the changelog.

- **Reason concatenation can produce noisy traces** when many rules deny
  for slightly different reasons. → Mitigation: trace already lists each
  rule's individual outcome; the aggregate reason is a summary, not the
  primary debug surface.

- **Future "import a friend's ruleset" flow becomes safe.** This is the
  intended payoff: composition no longer depends on where the import
  lands in the file.

## Migration Plan

1. Land the engine change behind a feature flag. (Reject — keeping a flag
   complicates the trust-hash story; the two changes need to ship together.)
2. Land everything in one commit, behind no flag, with the trust hash
   recomputation triggered automatically. Document in the changelog that
   trusted configs need a one-time re-trust after upgrade.

Lean: option 2.

## Open Questions

- **Reason aggregation format.** "; "-joined sorted reasons is the lean.
  An alternative is a structured `Vec<String>` carried through the result
  type, formatted at the trace boundary. The latter is more flexible but
  is a bigger surface change. Defer to v1 of the new model; revisit if
  trace output is judged too dense.
- **Should `(define …)` re-binding move to set semantics too?** Current
  proposal says no (last-wins, with a warning). The trust-hash change
  for defines (sorted serialisation) is consistent regardless: a
  re-binding is still a real semantic change because it overwrites a
  named slot.

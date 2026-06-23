## Context

`resolve-constant-argument-expansions` lets an argument word resolve against the
command's provably-constant **scalars**. A `for` loop variable is the next source
of provable values: `for k in A B C; do … "$k" …; done` binds `k` to one of three
literals, and every iteration runs. Today `constant_env` disqualifies loop
variables outright (`const_env.rs:55`), so the body's `"$k"` is unresolved and
floors the `:allow`.

The `for` list is already in the AST as `Command::For { var, words: Vec<Word>, body }`
(`crates/shell-parser/src/ast/mod.rs:32`), so — unlike arrays — no parser work is
needed. The list words are directly available and individually resolvable.

## Goals / Non-Goals

**Goals:**

- Resolve a loop variable to its provable value set when the list is statically
  literal, so body arguments built from it match rules on their real values.
- Reuse the existing across-units strictest-wins meet for the "all iterations
  run" semantics, rather than teaching matchers about value sets.
- Never under-ask: any non-enumerable list, in-body reassignment, or
  over-budget unroll falls back to today's flagged behaviour.

**Non-Goals:**

- `while`/`until` loops, C-style `for ((…))`, arithmetic ranges, `seq`, brace
  expansion `{1..3}` — no statically-literal list to enumerate in v1.
- Arrays and `"${arr[@]}"` loop lists — gated on parser support (separate
  change `model-bash-arrays`).
- Per-iteration correlation of bindings or facts beyond what the existing
  set-union binding semantics already provide.

## Decisions

### D1 — Unroll the body, do not teach matchers about sets

When a loop is enumerable, decompose emits the body's evaluation units **once per
list value**, each with the loop variable seeded as a provably-constant scalar in
that copy's `const_env`. The body's argument resolution is then exactly the
single-value path from `resolve-constant-argument-expansions`.

The alternative — a set-valued env where matchers test "all members match"
(universal) for the allow-floor and "any member matches" (existential) for
deny/ask — was rejected: provability stops being a pattern-independent
`arg_expansions` flag (it becomes per-pattern), forcing every matcher to learn
set semantics. Unrolling keeps matchers ignorant and reuses the across-units meet
that already encodes "all of these run, take the strictest".

### D2 — Enumerability is a structural test on the list and body

A loop is enumerable iff every list word resolves to a static literal (against
the existing constant env, so `for k in $CONST_SCALAR x` is fine) with no command
substitution, glob, `$@`/`$*`, or non-constant variable; and the loop variable is
not reassigned or `unset` in the body before its use. This reuses the same
straight-line, no-mutation discipline `constant_env` already applies to scalars,
scoped to the iteration.

### D3 — Bound unrolling with a total-unit budget

Nested enumerable loops multiply (|A|×|B|). A single total evaluation-unit budget
caps the blow-up; when unrolling a loop would exceed it, that loop is not
unrolled and its variable stays unresolved (flagged). The budget is a soundness
no-op — falling back to the single flagged walk only loses precision. Pick a
conservative default (e.g. 64 units) and `log`/document the cap so a silently
truncated unroll never reads as full coverage.

### D4 — Empty list is zero iterations

A statically-empty list (none in practice for a literal list, but defensively)
runs the body zero times and contributes no units — neither allow nor floor. This
falls out of unrolling naturally.

## Risks / Trade-offs

- **Unit explosion / cost.** Bounded by D3. Real ops loops are tiny (3–10
  values). Cartesian nesting is the worst case and is exactly what the budget
  guards.
- **Strictest-wins is conservative for partial matches.** If half the values
  match allow-rule X and the other half match a different allow-rule Y, the
  command is wholly allowed at runtime, but the meet could still ask if a value
  matches no rule. This only over-asks, never under-asks — acceptable.
- **Soundness rests on "every iteration runs".** A `for` over a literal list does
  run each value (modulo `break`/`continue`/early exit, which can only run
  *fewer* iterations — strictly safer for the allow direction). A loop nested in
  a conditional may not run at all; running the body more often than reality only
  adds asks, never removes them.
- **Depends on `resolve-constant-argument-expansions`.** If that lands second,
  this change's body resolution has nothing to consume. Sequence accordingly.

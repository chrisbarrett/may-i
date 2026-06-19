## Context

`model-bash-arrays` gives the evaluator a faithful array AST (array-literal
assignment value + subscripted `WordPart`) but resolves nothing. This change adds
the value analysis and resolution, completing the trio: scalar
(`resolve-constant-argument-expansions`), loop
(`enumerate-constant-loop-arguments`), and now array — all instances of one
primitive, *a statically-known finite sequence of literals*.

Arrays introduce one mechanism the other two lack: **word-count-changing
expansion**. A quoted `"${arr[@]}"` is a single AST word that expands to N argv
words. Scalar and loop resolution map one word to one value; this maps one word to
N values, shifting positional indices for downstream matchers.

## Goals / Non-Goals

**Goals:**

- A constant-array analysis yielding `name → ordered literal sequence`, sharing
  the scalar discipline (single unconditional assignment, no mutation, use-order).
- Resolve `${arr[i]}` (single), quoted `"${arr[@]}"` (argv splice), `${#arr[@]}`
  (count) against it.
- Keep `${arr[*]}`, unquoted `${arr[@]}`, and any mutated/non-literal array
  unresolved — never under-ask.

**Non-Goals:**

- `${arr[*]}` / unquoted `${arr[@]}` value resolution (IFS- and glob-dependent).
- Associative arrays entirely: `${m[key]}`, `"${m[@]}"`, `${m[*]}`, `${#m[@]}`
  all stay unresolved. Associative element order is unspecified in bash, so
  resolving `"${m[@]}"` to any order would be unsound; the resolver uses the
  array kind recorded by `model-bash-arrays` to exclude associative arrays. Only
  indexed arrays are resolved here.
- Transitive scalar-from-element (`x=${arr[0]}; … "$x"`) — like the scalar
  change's transitive non-goal, the RHS is not a pure literal.
- Namerefs / `${!ref[@]}` indirection.
- Slices `${arr[@]:1:2}` — defer.

## Decisions

### D1 — Generalise the provably-constant analysis to sequences

Extend `constant_env` to also produce constant arrays. Cleanest is one analysis
returning a value kind per name — `Scalar(String)` | `Array(Vec<String>)` —
so scalars remain the singleton case and the disqualification rules (single
assignment, no reassignment/`unset`, straight-line, use-order) extend uniformly.
Array-specific disqualifiers: any `arr[i]=`, `arr+=`, `unset 'arr[i]'`, sparse or
dynamic index in the literal, or a non-literal element.

### D2 — Resolve subscripts in argument-word construction

In `decompose_simple_command`, when resolving an argument word against the env,
dispatch on the subscript:

- `Index(literal i)` over a constant array → substitute element `i` as one
  literal, clear that word's `arg_expansions` entry (provable). Out-of-range or
  dynamic index → unresolved.
- `All` under a **quoted** context (`"${arr[@]}"`) → replace the single argv slot
  with N slots, one per element literal, each with a cleared `arg_expansions`
  entry. This is the only place argv length changes; do it while building the
  `args`/`arg_expansions` vectors so `args.len() == arg_expansions.len()` holds
  (the `anywhere_match` `debug_assert_eq!`).
- Length operator + `All` (`${#arr[@]}`) → substitute the element count.
- `Star`, unquoted `All`, dynamic index → leave as expansion-bearing.

Mixed words containing an `[@]` splice (`pre"${arr[@]}"post`) follow bash: the
first and last elements join the adjacent literals, interior elements are their
own words. v1 MAY restrict the splice to a lone-`"${arr[@]}"` word (the common
case) and leave the mixed-splice form unresolved; decide in 2.x and document.

### D3 — Reuse scalar resolution for the single-value cases

`${arr[i]}` and `${#arr[@]}` reduce to a single literal, so they flow through the
exact `Word::resolve` path the scalar change added — only the env lookup differs
(index into the sequence vs scalar fetch). Only the `[@]` splice is genuinely
new code.

## Risks / Trade-offs

- **Argv splice correctness.** Quoted `"${arr[@]}"` is one-word-per-element and
  IFS-independent — the safe case. The mixed-splice join rule is fiddly; D2
  permits deferring it to lone-word splices to keep v1 sound and simple.
- **Positional index shift.** Splicing N args changes positions for
  `(positional …)` / `(exact …)` matchers. Tests must cover a positional pattern
  after an `[@]` splice to confirm indices line up with what bash would pass.
- **Soundness vs IFS.** Excluding `[*]` and unquoted `[@]` avoids any IFS
  assumption; resolved cases are exactly what bash passes regardless of IFS.
- **Depends on two prior changes.** Needs the array AST (`model-bash-arrays`) and
  reuses scalar resolution (`resolve-constant-argument-expansions`). Land both
  first; this change is inert without the AST.
- **Analysis-shape change ripples.** Generalising `constant_env`'s return type to
  a value kind touches its scalar consumers (command-name and scalar-argument
  resolution). A proptest asserting scalar behaviour is unchanged guards the
  refactor.

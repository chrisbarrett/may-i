## Why

Quantifiers (`?`, `+`, `*`) wrap exactly one Pattern today, so an author
cannot quantify a *sequence*. The motivating case is terragrunt's
pass-through form: `terragrunt run -- <verb>`, where `--` is only legal
after `run`. The intended Pattern `(? "run" (? "--"))` — optionally
`run`, then optionally `--` — is currently rejected with "? must have
exactly one pattern", forcing a flat workaround that over-matches the
bogus `terragrunt -- <verb>` form. Sequence-group quantifiers close that
gap and unlock repeated/optional argument clusters generally.

## What Changes

- A quantifier head (`?`, `+`, `*`) MAY take **one or more** sub-patterns.
  More than one is an **implicit sequence**: the whole sub-sequence is the
  quantified unit. `(? "run" (? "--"))` means match nothing, `run`, or
  `run --`. Single-argument forms are unchanged.
- `+` and `*` over a sequence repeat the whole sub-sequence (Kleene
  semantics), with backtracking, replacing the current "one Pattern folded
  over consecutive args" model.
- A **matcher step budget** bounds positional matching so a pathological
  nested-quantifier Pattern cannot hang evaluation. The budget is a
  config-structure field with a high default; no surface syntax is exposed
  yet. Exceeding it yields no-match (decision floors to `:ask`).
- A **nullable-iteration guard**: a `+`/`*` iteration that consumes zero
  args terminates the loop, so nullable groups (`(* (? A))`) cannot loop
  forever.
- The expansion-bearing-word soundness check (a constrained match against
  a `$VAR`-bearing token cannot contribute to `:allow`) is threaded
  through every new group match path. This is hardened structurally so it
  cannot be silently dropped on a new code path (see design.md).
- **Decision**: implicit-seq is adopted over an explicit `(seq …)` head;
  any future quantifier *modifier* (separator, bounded repeat, group bind)
  gets its own head rather than trailing options on `? * +`.

No surface-syntax removals. Pre-1.0, so no back-compat shim; the change is
purely additive to the accepted grammar (previously-rejected forms now
parse).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities

- `patterns` (bucket: parsing, user-facing): quantifier Patterns accept a
  sequence of sub-patterns; `+`/`*` repeat the sub-sequence; serialization
  roundtrips the multi-pattern form. Trust-relevant — affects canonical
  form / hashing of any rule that uses the new form.
- `parser-engine-invariants` (bucket: contributor-internals): add a
  positional-matcher termination invariant — matching halts within the
  step budget and a zero-consuming repetition iteration terminates, for
  all Patterns including nested groups.

## Impact

- DSL grammar: `crates/config/src/pattern.rs` (`parse_positional_arg` no
  longer requires arity 2 for quantifier heads).
- Pattern AST: `crates/core/src/pattern.rs` — `PositionalArg` gains a
  recursive group term (`Single` vs `Group`).
- Matcher: `crates/engine/src/eval/positional.rs` — recursive group match
  with backtracking + step budget + nullable guard; fused match-evidence
  type carrying provenance.
- Pretty-printer: `crates/pp` / `to_doc` must render and round-trip the
  group form idempotently (`may-i fmt`).
- Trust hashing: `crates/engine/src/trust.rs` — canonical serialisation of
  the new node. Existing trusted configs are unaffected (no group use).
- Proptest generators: `crates/core/src/test_generators.rs` — generate
  groups with a depth cap; roundtrip and no-hang properties.
- Config structure: a matcher-budget field (no surface syntax yet).
- Docs: `CONTEXT.md` Quantifier glossary entry.

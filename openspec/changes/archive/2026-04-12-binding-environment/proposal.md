## Why

Named predicates (`define`) are resolved by inlining their bodies at load time.
This erases the user's vocabulary from trace output and leaves no AST node to
attach metadata (such as provenance for the upcoming load-trust feature).

## What Changes

- Stop inlining `Predicate::Named` references during the resolution step. The
  variant remains in the AST as a live variable reference.
- The evaluator carries a binding environment (`name → predicate body`) built
  from the config's `Define` list. `Predicate::Named` is resolved at eval time
  via env lookup.
- Load-time validation (duplicate detection, undefined ref checking, cycle
  detection) is unchanged.
- Trace output gains a "breakout" for variable references: the rule trace shows
  the define name at the point of use, and a separate nested section shows the
  define's body evaluated with its own trace annotations.

## Capabilities

### New Capabilities

- `eval-binding-env`: Evaluator binding environment — carrying defines as a
  runtime env rather than inlining, with `Predicate::Named` resolved via lookup.
- `var-trace-breakout`: Trace rendering of variable references — showing the
  define name in the rule trace and a breakout section with the expanded body
  and its annotations.

### Modified Capabilities

(none)

## Impact

- `crates/config/src/resolve.rs`: Remove the inlining step from
  `validate_and_resolve`. Keep all validation (duplicates, undefined refs,
  cycles).
- `crates/engine/src/eval/context.rs`: `EvalContext` gains a binding env.
- `crates/engine/src/eval/predicates.rs`: `Predicate::Named` performs env
  lookup + recursive eval.
- `crates/engine/src/fold.rs`: New fold callbacks for var entry/exit.
- `src/annotation.rs`, `src/output/mod.rs`, `src/output/json.rs`: Render var
  breakout sections in both human-readable and JSON trace formats.
- Existing tests that assert on resolved (inlined) predicates will need
  updating.

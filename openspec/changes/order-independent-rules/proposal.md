## Why

Rule evaluation today returns the first matching rule's decision and stops.
This is not written down anywhere — it's an emergent property of the engine —
and it silently undermines the trust+hashing model that lets users compose
rules from multiple sources (`(load …)` files, future "import a friend's
ruleset"). With first-match semantics, dropping a `(load …)` near the top of a
file can change the meaning of every rule below it; the trust hash captures
ordered closures partly to compensate.

The intended user-level model is: **the program name selects the set of rules
that apply, every applicable rule is evaluated, and the strictest decision
wins**. Order doesn't matter. This makes rule composition predictable —
importing rules from anywhere is safe as long as you've approved them — and it
matches how the engine already aggregates decisions across compound commands
(`cmd1 && cmd2`).

## What Changes

- **BREAKING (engine semantics):** `Evaluator::evaluate` now runs every rule
  whose command pattern matches `ctx.command`, collects each non-Nil result,
  and returns the strictest (`Deny > Ask > Allow`). First-match early-exit is
  removed.
- **BREAKING (trust hashing):** The trust hash is computed over a
  *canonical-ordered* set of rules (e.g. by the canonical s-expression
  serialisation, sorted lexically) rather than the source-order list. Adding a
  comment, reordering rules, or moving rules between `(load …)` files leaves
  the hash unchanged; only semantic content changes it.
- **New REFERENCE.md guidance** explaining the model: order doesn't matter,
  strictest wins, deny rules don't need to come first.
- **Tests updated** wherever a fixture happened to rely on first-match
  ordering. Property test added: shuffling rules is a no-op for the engine
  output.

## Capabilities

### New Capabilities

- `rule-evaluation`: the user-level model for how a command resolves to a
  decision. Captures: program-name selection of the applicable set,
  all-rules-run, strictest-wins aggregation, order independence as an
  invariant, and the relationship to the per-segment aggregation in
  `evaluate_command`.

### Modified Capabilities

- `trust-hashing`: drop the "ordered closure" requirement and the "reordering
  rules changes the hash" scenario. Hash is computed over a canonical set
  (deterministic but order-independent serialisation) so semantically
  equivalent configs produce the same hash.

## Impact

- `crates/engine/src/eval/entry.rs::Evaluator::evaluate` — replace early-return
  loop with a fold that collects results and picks the strictest.
- `crates/engine/src/eval/command.rs` — the existing "strictest across
  segments" aggregation already matches the new model; no logic change, but
  the comment trail and trace messages should now reuse the same vocabulary.
- Trust hashing module (wherever the per-program hash is computed) — switch
  to canonical sorted serialisation.
- `tests/` — audit for fixtures that depend on first-match. Update the
  reordering-changes-hash trust test. Add a shuffle-property test for rule
  evaluation.
- `REFERENCE.md` — rewrite the "How rules resolve" section.
- Snapshots — likely some shifts where multiple rules previously lost to the
  first match.

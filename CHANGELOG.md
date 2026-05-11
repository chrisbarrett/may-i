# Changelog

## Unreleased

### Breaking changes

- **Rule evaluation is now order-independent.** Every `(rule …)` whose
  command pattern matches the input runs, and the strictest decision
  wins (`deny > ask > allow`). The previous first-match-wins behaviour
  is removed.

  In practice, an `(allow)` catch-all followed by a more specific
  `(deny …)` used to leave the `(deny …)` unreachable; under the new
  model the `(deny …)` is honoured. If you relied on shadowing,
  encode the intent in pattern bodies (`(when (not …) …)`,
  `(cond …)`, `(if …)`) rather than source order.

  When two or more rules tie at the strictest decision, their distinct
  reasons are deduplicated, sorted lexically and joined with `"; "`
  so the aggregate result does not depend on rule order.

- **Trust hashes are recomputed over a canonical, order-independent
  set of rules.** Reordering rules, moving rules between `(load …)`
  files, or editing comments and whitespace no longer changes the
  trust hash for a program; only changes to the rule content itself
  do. As a one-time effect of upgrading, trusted configs that have
  `(load …)`-sourced rules will need to be re-trusted (`may-i trust`)
  the first time they run after the upgrade.

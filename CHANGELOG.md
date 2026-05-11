# Changelog

## Unreleased

### Security fixes

- **`(authorise #var)` over `(rest …)`-style bindings could be bypassed by
  inner argv tokens containing shell metacharacters.** When a token-list
  binding (`(rest …)`, `(positional … *|+)`) was authorised, the tokens
  were joined with single spaces and re-parsed. A token like
  `"echo a && rm -rf /tmp/x"` — delivered by the outer shell as one
  quoted argument — was then split at the unquoted `&&`, exposing the
  inner `rm` at the wrapper's frame rather than as a child of the
  intended inner program (`bash -c …`, `sh -c …`). Token-list recursion
  now preserves each outer-shell-established boundary: argv[0] is the
  inner command name and argv[1..] is the inner argv. Single-element
  token lists continue to re-parse (no boundary information to lose).
  Users with wrapper rules (sudo, ssh, xargs, nix-shell, mise, watch,
  …) should re-review their policies — previously-`:allow` outcomes for
  compound inner commands may now correctly resolve to `:ask` or
  `:deny`. `(many-till …)` captures (e.g. `find -exec …`) intentionally
  retain the join-and-parse behaviour: those tokens are authored by the
  user with spaces as separators, not delivered by the outer shell as a
  single quoted argument.

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

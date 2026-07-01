# Changelog

## Unreleased

### Security fixes

- **`export NAME=…` / `declare -x NAME=…` no longer slip past the env-write
  floor.** The floor previously keyed on whether an assignment landed in a
  simple command's assignment list — a parsing artifact that missed an exported
  scalar (`export LD_PRELOAD=/evil.so; cmd` evaluated as `:allow` even though
  every later command inherited it). The floor now keys on whether a write
  **reaches a child process**: a command prefix, an `export`/`declare -x`/
  `typeset -x`/`readonly -x`/`local -x`, a bare reassignment of a name present
  in the entry environment, or any assignment under `set -a` / `set -o
  allexport`. Such a write floors to `:ask` unless an `(env NAME (allow))` (or
  `(safe-env-vars …)`) lifts it. The new **entry environment** input
  (names-only, never values) supplies the inherited-export set: `may-i hook`
  captures it live, `may-i eval` injects it via `--env`/`--inherit-env`, and
  `may-i check` stays hermetic via `(with-env …)`.

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

- **Shell-local env writes no longer floor.** A bare assignment of a name *not*
  in the entry environment, a `declare`/`local`/`readonly` without `-x`, and an
  array literal (`name=(…)`, `declare -A m=([k]=v)`) are shell-local — they set
  a variable no child inherits — and now evaluate as `:allow` instead of
  flooring to `:ask`. The prior behaviour was a shape-keyed bug (e.g.
  `declare -A m=([k]=v)` over-blocked while `export LD_PRELOAD=…` under-blocked).
  A config that wants a specific shell-local name to floor can still write
  `(env NAME (ask))`. New affordances: the `(scope prefix|export|bare|
  reaches-child)` predicate inside an `(env …)` decision, and `(with-env [NAME
  …] …)` in `(check …)` cases. (Internal: the parser now lifts a declaration
  builtin's scalar `NAME=value` argument out of the command's argv into its
  assignment list — a rule matching `export`/`declare` *arguments* by value
  would no longer see the `NAME=value` token, though no prelude rule does.)

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

### Behaviour changes

- **Undeclared long flags no longer blindly swallow the next token.**
  Under gnu-shaped styles, a `--long` flag that is not declared as a
  `(parameter …)` (nor implicitly registered by a rule) used to consume
  the following token as its value unconditionally — eating a following
  flag, the `--` flag-stop, or a subcommand, and corrupting the
  positional residual that `(positional …)` matches. The tokeniser now
  consumes that token only when it is a **plausible value**: not itself
  flag-shaped (begins with `-`/`--` and a letter) and not the `--`
  flag-stop. Negative numbers (`-5`) and bare `-` remain values; the
  `--` flag-stop is never absorbed. Declared `(parameter …)` flags are
  unchanged (they consume regardless of shape), and a flag declared as a
  boolean `(flag …)` is now treated as value-less so it never consumes
  its successor.

  This re-tokenises some commands containing undeclared long flags.
  The shift is mostly `:ask → :allow` (e.g. `cargo run --quiet --bin
  may-i -- eval` now keeps its `run … --` adjacency). A narrow case can
  shift the other way: a trailing undeclared boolean before a guarded
  `(positional …)` (e.g. `cargo --release build`) still consumes the
  following token, so keep security deny-guards on `(flag …)` /
  `(anywhere …)`, which scan raw argv, rather than on `(positional …)`.
  Not trust-relevant — no rule participation, approval, or hash changes.

- **Arity guesses are surfaced in the trace.** When the tokeniser must
  guess an undeclared long flag's arity (an undeclared gnu-shaped long
  flag immediately followed by a plausible value), the trace now carries
  an `arity guess:` Advisory naming the flag and the consumed token, in
  both the human and `--json` (`"type": "arity_guess"`) trace surfaces.
  The Advisory is informational and never changes the decision.

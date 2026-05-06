## Why

Two related gaps surface together:

1. **No repo-local config.** Users want a `.may-i.lisp` (and friends) at a
   repo or worktree root so that project-specific rules — "in this repo,
   `cargo test` is allowed" — travel with the project, not with the
   user. Today the search path is global only: CLI flag → `$MAYI_CONFIG` →
   XDG → `~/.config/may-i/config.lisp`. Adding a project layer needs an
   extension to the resolver, but the security argument has to land first.

2. **The engine is first-match-wins, not most-strict-wins.** The
   `Decision` enum declares `Allow < Ask < Deny` and derives `Ord`
   (`crates/core/src/primitives.rs:51-57`), but nothing uses the
   ordering. The evaluator returns on the first matching rule
   (`crates/engine/src/eval/entry.rs:126-143`). A loaded
   `(rule "rm" (effect :allow))` placed before a primary
   `(rule "rm" (effect :deny ...))` shadows the deny. Trust filtering
   removes unapproved Loaded rules before evaluation, so the attack only
   lands on a rule that the user has already approved — but at trust-review
   time the user inspects rules in isolation, with no signal that an
   `:allow` overlaps with an existing primary `:deny`. Order-as-semantics is
   a real sharp edge that a multi-source config makes much sharper.

Shipping repo-local discovery without fixing the engine is the dangerous
combination. Bundling them keeps the security argument honest: loaded
configs cannot widen primary policy, full stop, because the lattice
combine guarantees it — not because the user reviewed carefully.

## What Changes

### Engine: most-strict-wins rule combination

- Replace first-match-wins evaluation with a fold over **all** matching
  rules: the resulting `Decision` is the maximum under
  `Allow < Ask < Deny`. Order between matching rules no longer affects
  the decision.
- When multiple rules tie at the most-strict effect, the **earliest in
  source order** wins for `reason` reporting (deterministic, useful for
  trace output). Source order is: primary config rules first (in file
  order), then loaded files in load order.
- When no rule matches, the result remains `Ask` (lattice bottom for
  unmatched commands; unchanged from today).
- Per-segment evaluation (`engine-segment-decisions`) is unchanged in
  shape — each segment still independently evaluates against the rule
  list. Only the combine step within a segment changes.

### Discovery: repo-local and worktree-local config

- Resolver gains a new layer between `$MAYI_CONFIG` and XDG:
  **repo-local discovery**.
- Discovery uses `git rev-parse --show-toplevel` against the current
  working directory; falls back to walking parents for `.git`, `.hg`, or
  `.jj` markers if `git` is not on PATH.
- Worktrees: `git rev-parse --show-toplevel` returns the worktree root,
  so each worktree gets its own opt-in trust (correct behaviour).
- File set discovered at the repo root, in this order, all merged into
  the primary config as if loaded:
  - `.may-i.lisp`
  - `.may-i/**/*.lisp` (sorted lexically; cycle detection inherited
    from the existing `(load …)` pipeline)
  - `.may-i.local.lisp`
  - `.claude/may-i.lisp`
  - `.claude/may-i.local.lisp`
- Missing files are silently skipped. Discovery never errors on
  "no repo found" — it just contributes nothing.
- All discovered rules carry `Provenance::Loaded { path }` and are
  subject to the existing trust gate. They are inert until approved by
  `may-i trust`.

### Trust: provenance unchanged in shape

The trust system already filters un-approved `Loaded` rules. With
most-strict-wins combine in place, even an approved loaded rule cannot
widen primary policy: the strictest match across **all** sources wins.
Trust review continues to show canonical rule forms; the security
argument no longer hinges on the user catching subtle ordering attacks.

## Capabilities

### New Capabilities

- `rule-combination`: top-level rule evaluation combines matching
  rules under the `Decision` lattice (`Allow < Ask < Deny`); the
  result is the most-strict effect among matches. Order-independent.
- `repo-local-config`: the resolver discovers project-scoped config
  files at the repo or worktree root and merges them into the loaded
  config tree as `Loaded` rules.

### Modified Capabilities

- `trust-provenance`: extends the `Loaded` provenance set to include
  files discovered via repo-local resolution. No change to hash
  algorithm, store format, or per-rule trust semantics.

## Impact

- `crates/engine/src/eval/entry.rs` — replace first-match return loop
  with a fold over all matches that selects the most-strict
  `Decision` and the earliest-in-source-order `reason`.
- `crates/engine/src/test_generators/effect_eval_tests.rs` — update
  `first_matching_rule_wins` test (and any peers) to assert
  most-strict semantics. Add property tests covering order-invariance
  and lattice-bottom default.
- `crates/config/src/io.rs` — extend `resolve_path` / load pipeline
  with repo-local discovery; emit synthetic `(load ...)` forms or
  splice the discovered files into the load result with `Loaded`
  provenance preserved.
- `src/main.rs` — if needed, plumb CWD through to the resolver;
  document the new layer in `--help`.
- Tests — new property tests for rule-combine; integration tests for
  discovery (using `tempfile` repos with various marker
  combinations); snapshot tests for trust-review output across the
  new file types.
- User-visible behaviour change — first-match-wins users may see
  different decisions after the engine swap. Mitigated by the
  migration audit step in tasks.md and a release note. Property tests
  in the rule-combination spec encode the new contract.

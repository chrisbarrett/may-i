# Tasks

## 1. Capability config surface

- [x] 1.1 Write failing parse tests: `(env "X" (allow|ask|deny))` and
  `(redirect PAT (allow))` (and arity-1 `(redirect (allow))` = any target) parse
  into `SecurityConfig`; a bare/invalid decision is a parse error naming the form.
- [x] 1.2 Parse `(env NAME DECISION)` into a name→decision map on
  `SecurityConfig`, split by provenance (primary vs loaded) like `safe_env_vars`.
- [x] 1.3 Parse `(redirect PAT DECISION)` (PAT optional → any target) into a
  list of (target-Pattern, decision), same provenance split.
- [x] 1.4 Keep `(safe-env-vars …)` as a parsed alias that lowers to
  `(env NAME (allow))`; assert old configs still load.
- [x] 1.5 Parse the capability DECISION position as a full `Effect` expression
  (reuse the rule-body parser), not just a terminal.
- [x] 1.6 Write failing validation tests, then add a load-time check rejecting
  argv/binding constructs in capability position (`CommandPattern`, `ArgPattern`,
  `Authorise`, `Bound`, `Matches`, `Every`, `Some`, and a `Named` resolving to
  any of those), with a diagnostic naming the offending form.

## 2. Decompose: write/read split and secret taint

- [x] 2.1 Write failing decompose tests: `sort < f` emits no floor unit; `tee
  /tmp/x` emits a write `RedirectTarget`; `curl ?$AWS_TOKEN` emits a read-taint
  unit naming `AWS_TOKEN`; `aws s3 cp` emits none.
- [x] 2.2 Split `EvalUnit::RedirectTarget` into write vs read (or carry a
  `write: bool`); stop emitting floor units for read redirections. Preserve
  embedded-command extraction from read redirections (`< <(cmd)`, heredocs).
- [x] 2.3 Emit a taint unit when an argv word carries a `WordPart::Parameter` /
  `ParameterExpansion` / `ParameterExpansionOp` whose `name` is in the tainted
  (ask/deny) env set.
- [x] 2.4 Cover every position bash expands a tainted variable into command text
  (post-review hardening; see the read-site enumeration in
  shell-command-security-model and design D3). Read sites: argv words; command
  prefix **and** bare assignment values; `for`/`case` words; unquoted heredoc
  bodies and herestrings on simple **and** compound redirect wrappers; redirect
  target pathnames (`> /tmp/$NAME`, `< /tmp/$NAME`). Expansion shapes: operator
  operands (`${X:-$NAME}`), array subscripts (`${arr[$NAME]}`), transform
  operators (`${NAME@Q}`, via leading-identifier normalization), glob brackets
  (`[$NAME]`), brace-expansion elements (`{a,$NAME}`), and arithmetic
  (`$((NAME))`, `$[NAME]` — the latter lexed to `WordPart::Arithmetic`). Builtin
  arithmetic (`let`, `((…))`, `declare -i`) is a documented out-of-model
  carve-out.

## 3. Eval: capabilities in the segment meet

- [x] 3.1 Write failing eval scenarios mirroring every spec scenario (capability
  meet, env write allow/ask/deny, read taint, write-only allow vs
  expansion-soundness, redirect-write capability allow/non-match,
  expansion-bearing target).
- [x] 3.2 Resolve `EnvPrefix` against the effective env capability set:
  `(allow)` passes through; absent → floor; `(ask)`/`(deny)` contribute.
- [x] 3.3 Resolve the read-taint unit to the env capability's decision and fold
  it into the segment meet.
- [x] 3.4 Resolve a write `RedirectTarget` against the redirect capabilities,
  applying the asymmetric-soundness check to expansion-bearing targets before any
  capability can lift the floor.
- [x] 3.5 Evaluate the capability DECISION expression against the active facts
  with an empty binding environment (reuse the `Effect` evaluator); contribute
  its resulting decision to the segment meet. Cover fact conditionals selecting
  different decisions under different facts.

## 4. Trust scope generalization

- [x] 4.1 Write failing trust tests: a loaded `(env "FOO" (allow))` /
  `(redirect …)` is inert until its scope is approved; a primary-config form is
  always effective.
- [x] 4.2 Generalize the `:safe-env-vars` trust scope into per-axis scopes
  (`:env`, `:redirect`); hash the merged loaded sets under them.
- [x] 4.3 Update `may-i trust` to list/approve the new scopes.

## 5. Migration

- [x] 5.1 Write a failing migration test: `(safe-env-vars "A" "B")` rewrites to
  `(env "A" (allow)) (env "B" (allow))`; a prior `:safe-env-vars` approval
  re-hashes under the generalized scope and stays trusted (Class A).
- [x] 5.2 Implement the migration and register it in the migration system.

## 6. Docs and vocabulary

- [x] 6.1 CONTEXT.md: add **Capability** (user vocab) — a config-level decision
  over a shell-language effect, combined into the segment meet; generalize
  **Decision** from "the answer a rule gives" to "the answer a rule or capability
  gives", noting `:allow` is the lattice bottom so a capability never widens past
  a command's own decision. Note its decision is the fact-conditioned subset of
  the rule-body language (facts + conditionals, no argv analysis). Record the env
  read/write asymmetry and the structural-not-dataflow boundary under
  Relationships / Flagged ambiguities.
- [x] 6.2 REFERENCE.md (`may-i reference`): document `(env …)` and `(redirect …)`
  and the `safe-env-vars` migration, or record "verified, no surface change" if
  deferred. (Doc-sync gate — user-facing capability.)
- [x] 6.3 Remove the superseded `rules-grant-redirect-capability` draft change.

## 7. Verification

- [x] 7.1 `cargo fmt`; `may-i fmt examples/*.lisp` if touched.
- [x] 7.2 Full test suite green; add proptests where a branch is proptest-reachable.
- [x] 7.3 `cargo tarpaulin`; inspect `lcov.info` for uncovered capability seams.
- [x] 7.4 `openspec validate redirect-and-env-capabilities` and the spec
  doc-sync validator pass.

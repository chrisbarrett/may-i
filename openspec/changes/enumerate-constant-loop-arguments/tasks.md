## 1. Enumerability analysis

- [x] 1.1 Add a failing test in `crates/shell-parser`: a `for` over a literal list
      exposes its values as enumerable; a list with `$(…)`, a glob, `$@`/`$*`, or
      a non-constant variable does not. Confirm red.
- [x] 1.2 Replace the unconditional loop-variable disqualification in
      `constant_env` (`const_env.rs:55`) with the enumerability test: literal list
      words, loop variable not reassigned/`unset` in the body before use.
      (Deviation: the scalar `constant_env` map still excludes the loop var —
      it is genuinely multi-valued — and a new `enumerable_for_values` exposes
      the value set, consumed by `decompose`. The disqualification in `collect`
      is unchanged because the scalar map is the wrong home for a value *set*.)
- [x] 1.3 Proptest: enumerability is invariant to reordering unrelated commands in
      the body; flips off when a list word is made dynamic or the variable is
      reassigned before use.

## 2. Unrolling in `decompose`

- [x] 2.1 Add a failing engine test: `for k in a b c; do aws s3 cp "s3://bkt/$k" /tmp/x; done`
      with an allow matching all three sources resolves to `:allow`, no floor.
      Confirm red.
- [x] 2.2 In `decompose`, when a `for` loop is enumerable, emit the body's
      `EvalUnit`s once per list value with the loop variable seeded into each
      copy's `const_env`; otherwise walk the body once as today.
- [x] 2.3 Enforce the total evaluation-unit budget; over budget, fall back to the
      single non-unrolled walk (loop variable unresolved). (Deviation: no `log`
      facility exists in the pure-eval `engine`/`shell-parser` crates — adding a
      logging dependency conflicts with "Eval is pure: no IO". The cap is
      documented in `UNROLL_UNIT_BUDGET`'s doc comment and the fallback floors
      to `:ask`, so a truncated unroll surfaces as a visible ask, never as full
      coverage.)

## 3. Combination and boundary scenarios

- [x] 3.1 Test: one list value fails the allow pattern → meet yields at least `:ask`.
- [x] 3.2 Test: a value matching a deny rule → meet yields `:deny`.
- [x] 3.3 Test: nested enumerable loops within budget unroll to the product; over
      budget fall back without under-asking.
- [x] 3.4 Test: non-literal list and in-body reassignment both stay flagged.
- [x] 3.5 Metamorphic proptest: each unrolled per-value decision (and reason)
      equals the bare command with that literal substituted for `$k`; the
      multi-value meet equals the strictest per-literal decision.

## 4. Verification

- [x] 4.1 `cargo fmt`; full `cargo test` across `shell-parser` and `engine`
      (and the whole workspace) — all green.
- [x] 4.2 `cargo tarpaulin`; inspected coverage for the unroll/budget path. The
      new decompose functions (`build_unroll_plan`/`plan_walk`/`count_body_units`/
      `collect_simple_command_units`) are covered; added const_env unit tests for
      the in-body prefix-assignment and `export` reassignment branches a proptest
      could not reach.
- [x] 4.3 Confirmed dependence on `resolve-constant-argument-expansions` holds:
      the seeded loop-variable scalar flows through `decompose_simple_command`'s
      `resolve_argument_words`/`resolve_command_name` (the merged single-value
      path). No DSL/config/trust-hash surface changed; no migration. The two
      public additions (`enumerable_for_values`, internal decompose helpers) are
      analysis-only.
- [x] 4.4 Reviewed `REFERENCE.md`: it carries no description of loop-variable /
      unresolved-expansion handling (the scalar change added none either), so
      this is **verified, no surface change** — the improvement is internal
      precision with no user-facing DSL/config surface.

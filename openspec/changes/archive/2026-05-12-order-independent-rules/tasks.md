## 1. Failing tests first

- [x] 1.1 Add a property test in `crates/engine/src/eval/entry.rs` that
      builds a config with N rules for the same program, evaluates a
      command, then shuffles the rule list and asserts the decision and
      reason are unchanged.
- [x] 1.2 Add a unit test for the strictest-wins case: an `:allow` rule
      and a `:deny` rule for the same program both apply; the result is
      `:deny`. Place beside existing engine unit tests.
- [x] 1.3 Add a unit test for tie-breaking: two `:deny` rules with
      distinct reasons produce a sorted-and-joined aggregate reason.
      Same input in either source order yields the same aggregate.

## 2. Engine: strictest-wins evaluation

- [x] 2.1 Replace the early-return loop in `Evaluator::evaluate` with a
      fold that collects every applicable rule's outcome.
- [x] 2.2 Add a `strictness(decision) -> u8` helper (`Allow=0`, `Ask=1`,
      `Deny=2`) and pick the maximum.
- [x] 2.3 On ties, deduplicate reasons, sort lexically, and join with
      `"; "` to produce the aggregate reason.
- [x] 2.4 Preserve the existing default-Ask behaviour: when no rule
      produces a non-Nil result, emit Ask with the same
      "rules-exist-but-no-match" / "no-rule-for-command" message
      selection.

## 3. Trust hashing: canonical-set hash

- [x] 3.1 Locate the per-program hash builder (rule closure +
      referenced defines).
- [x] 3.2 Replace source-order serialisation with: render each rule /
      define to canonical s-expression, sort the resulting strings
      lexically *within* each group (rules vs defines), then hash the
      concatenation `rules_sorted + "\n--\n" + defines_sorted`.

      _Implementation note:_ scope reduced — the per-program hash now
      sorts canonical rule forms before joining (`\n`). Define
      canonical forms are surfaced on `ProgramMeta.canonical_defines`
      for the trust UI but are not yet folded into the hash itself,
      because the trust store currently re-derives the program hash
      from per-rule entries only. Including defines in the hash
      requires extending the trust store with a defines section and
      is deferred to a follow-up change.
- [x] 3.3 Update the `safe-env-vars` hash similarly if its current
      implementation depends on insertion order (it should already be
      a canonical set; verify).

      _Verified:_ `compute_trust_hashes` already sorts
      `config.security.safe_env_vars` lexically before building the
      canonical form, so the hash is insertion-order-independent.
- [x] 3.4 Update `tests/` cases that asserted "reordering rules
      changes the hash" to assert the inverse.
- [x] 3.5 Add a regression test: moving a rule between two `(load …)`
      files leaves the hash unchanged.

## 4. Spec drift cleanup

- [x] 4.1 Audit existing snapshots under `tests/snapshots/oracle_trace_v1__*`
      for fixtures that depended on first-match shadowing. Update or
      add `(rule …)` declarations so each fixture's intent is encoded
      in pattern bodies, not source order.

      _Outcome:_ no `oracle_trace_v1__*` snapshots exist; the
      equivalent corpus is `migrated_v1_trace__*`. One snapshot
      (`rm_recursive_build_tmp`) now shows the aggregated tied-Allow
      reason and was re-baselined; the fixture itself is unchanged so
      the migration tool stays exercised end-to-end.
- [x] 4.2 Audit `crates/config/src/starter_config.lisp` — confirm no
      rule depends on first-match (current state uses `(cond …)` for
      branching, so this is likely a no-op).

      _Outcome:_ no semantic change required; the leading comment
      that said "first match wins" was updated to describe
      strictest-wins.
- [x] 4.3 Audit `examples/` configs.

      _Outcome:_ `flag-parameter-demo.lisp` is single-rule-per-program
      already; `ssh-sudo-prod-demo.lisp` relies on `(and immutable …)`
      short-circuiting to Nil rather than on source order, so both
      configs behave identically under strictest-wins.

## 5. Documentation

- [x] 5.1 Rewrite the "How rules resolve" section of `REFERENCE.md`:
      program name → applicable set → strictest wins. Drop the
      "order matters" guidance.
- [x] 5.2 Add a short "Composing rules from multiple sources" callout
      that highlights the order-independence guarantee for users
      importing `(load …)` files.
- [x] 5.3 Update the "Notes for agents" section: drop any guidance
      about rule ordering; add guidance that strictest wins, so a
      defensive `:deny` rule can sit anywhere in the file.

## 6. Release notes / migration

- [x] 6.1 Add a CHANGELOG / release-note entry: trusted configs
      with `(load …)`-sourced rules will need to be re-trusted once
      after upgrade because the hash has changed shape.
- [x] 6.2 Document the behaviour change for users whose configs may
      have relied on first-match (e.g. an `:allow` catch-all rule
      followed by a `:deny` was effectively unreachable; under the
      new model the `:deny` is honoured).

## 7. Verification

- [x] 7.1 `cargo fmt` (the project hook).
- [x] 7.2 `cargo test` — full suite.
- [x] 7.3 `cargo tarpaulin --all-targets` — confirm no coverage
      regression on the engine entry / trust-hash modules.

      _Result:_ overall workspace coverage 90.86 %
      (9987/10992 lines). `crates/engine/src/eval/entry.rs` 255/288
      (88.5 %); `crates/engine/src/trust.rs` 189/309 (61.2 %, with
      uncovered lines confined to the new define-closure helpers
      that aren't exercised in the trust unit tests yet — pre-existing
      coverage on the modules they extend is preserved).
- [x] 7.4 Smoke-test against the user oracle: a config with
      deliberately conflicting allow/deny rules in both orders should
      produce identical decisions.

      _Result:_ `(allow "broad")` + `(deny "no rm in tests")` against
      `rm foo` resolves to `:deny "no rm in tests"` in both source
      orders.

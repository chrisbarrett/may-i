## 1. Use-order-awareness in `constant_env` (D2)

- [ ] 1.1 Add a failing test in `crates/shell-parser/src/tests/const_env.rs`:
      `$B x; B=rm` (use before sole assignment) MUST NOT yield `B` as constant.
      Confirm it is red (the gap exists) before fixing.
- [ ] 1.2 Make `constant_env` use-order-aware: a name used as an expansion
      before its sole qualifying assignment on the straight-line spine is
      disqualified. Keep straight-line assign-then-use qualifying.
- [ ] 1.3 Add a proptest: for a straight-line `NAME=lit; … <use>`, qualification
      is invariant to inserting unrelated commands between assignment and use,
      but flips to disqualified when the use is moved before the assignment.
- [ ] 1.4 Confirm the existing command-name scenario
      `Use before the assignment stays dynamic` (`$B x; B=rm`) now passes via the
      engine path.

## 2. Resolve argument words in `decompose` (D1)

- [ ] 2.1 Add a failing engine test: `BUCKET=b; KEY=k; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x`
      with an allow rule whose target matches `s3://b/k` resolves to `:allow`
      with no `unresolved shell expansion …` floor. Confirm red.
- [ ] 2.2 In `decompose_simple_command` (`crates/engine/src/eval/decompose.rs`),
      resolve each argument word against `const_env`: on a fully-literal resolve,
      push the resolved value into `args` and set its `arg_expansions` entry to
      `None`; otherwise keep `w.to_str()` and the existing expansion-bearing flag.
- [ ] 2.3 Preserve `args.len() == arg_expansions.len()` (the `anywhere_match`
      `debug_assert_eq!`); update the `decompose.rs:618-619` comment that states
      "Argument words are never resolved here".

## 3. Boundary and soundness scenarios

- [ ] 3.1 Test: partially-resolved word `s3://$BUCKET/$KEY` with only `BUCKET`
      constant stays expansion-bearing and floors an `:allow` to `:ask`.
- [ ] 3.2 Test: resolved argument is gated by a deny rule — `P=/etc/shadow; cat "$P"`
      with a deny on `cat /etc/shadow` yields `:deny`.
- [ ] 3.3 Test: argument from a substitution `T=$(mktemp); rm "$T"` stays
      expansion-bearing (not provably constant).
- [ ] 3.4 Test: argument used before assignment `rm "$T"; T=/tmp/x` stays
      expansion-bearing (covers D2 on the argument path).
- [ ] 3.5 Metamorphic proptest: for a provably-constant argument, the decision
      and rule classification equal those of the same command with the resolved
      literal written directly in place of the `$VAR`.

## 4. Verification

- [ ] 4.1 `cargo fmt`; full `cargo test` across `shell-parser` and `engine`.
- [ ] 4.2 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the
      new resolution path and add unit tests for any a proptest cannot reach.
- [ ] 4.3 Confirm no DSL/config/trust-hash surface changed (no migration needed);
      verify the two in-progress substitution changes are untouched.
- [ ] 4.4 Review `REFERENCE.md`: update any description of unresolved-expansion
      flooring / constant-variable resolution to cover argument words, or record
      "verified, no surface change" if the behaviour is not documented there.

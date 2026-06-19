## 1. Thread the inherited live-name set into decompose

- [ ] 1.1 Write a failing decompose test: `resolve() { echo hi; }; dest=$(resolve)` yields an `EmbeddedCommand` whose carried `inherited_fns` contains `resolve`; `dest=$(resolve); resolve() { echo hi; }` yields one whose set does NOT (forward reference, not live at the site).
- [ ] 1.2 Add `inherited_fns: HashSet<String>` to `EvalUnit::EmbeddedCommand`; give `decompose` an `inherited_fns` parameter (empty at top level). Compute each substitution's carried set as `inherited_fns ∪ established-at-the-substitution-span`, reusing the `live_local_call_spans` liveness machinery (Spine vs Deferred mode at the substitution's location). Default empty reproduces current behaviour.

## 2. Seed the embedded evaluation with the inherited set

- [ ] 2.1 Write a failing engine test: the `dest=$(resolve)` case (live) resolves to `:allow` with no `No rule for command …`; the forward-reference case asks.
- [ ] 2.2 Thread the carried set from `EvalUnit::EmbeddedCommand` through `eval_units` (`command.rs:304`) into the inner `decompose`, so the inner `live_local_call_spans` seeds its `live`/`established` sets with the inherited names.

## 3. Recursive propagation through nested substitutions

- [ ] 3.1 Write a failing engine test: `g() { echo x; }; f() { echo y; }; out=$(f $(g))` recognises both `f` and `g` as internal (neither asks); a nested forward reference is NOT recognised.
- [ ] 3.2 Ensure the inner `decompose` computes its own nested substitutions' carried sets as `received-inherited ∪ locally-live-here`, so propagation flows through the existing `depth + 1` recursion without a depth cap.

## 4. Metamorphic equivalence oracle

- [ ] 4.1 Write a metamorphic proptest: for a generated script and a call site, assert the classification of the call inside `x=$(call)` at position P equals the classification of the bare `call` at P (the invariant in D4). Use the bare-call path as ground truth.
- [ ] 4.2 Add the spec scenarios as engine tests: live-in-subst allows; forward-ref asks; non-defined (`kubectl`) asks; body-site recognised; nested recognised; dangerous body still asks.

## 5. Soundness & coverage

- [ ] 5.1 Confirm a substitution-recognised function's body is still authorised at its definition (`wipe() { rm -rf "$d"; }; x=$(wipe)` asks on `rm`).
- [ ] 5.2 Run the motivating script (`resolve`/`main` under `set -euo pipefail`) in hook mode; confirm the substitution call no longer asks.
- [ ] 5.3 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered branches in the new inherited-set paths.
- [ ] 5.4 Check in any new `proptest-regressions/` files.
- [ ] 5.5 Review REFERENCE.md for surface change: this change adds no DSL, config, or error-message *form* (the existing `No rule for command …` reason simply fires less often). Record "verified, no surface change" unless a behavioural note is warranted.

## 1. Tag substitution origin at the owning decompose pass

- [ ] 1.1 Write a failing decompose test: an `EmbeddedCommand` from `dest=$(x)` carries an assignment-target origin (`dest`); from `grep "$(x)" f` a simple-command origin (`grep`); from `cat > "$(x)"` a redirect-target origin. The `set -euo pipefail; main() { dest=$(x); }; main` case carries the assignment origin, NOT `set`.
- [ ] 1.2 Add a `SubstitutionOrigin` descriptor field to `EvalUnit::EmbeddedCommand`. Set it in each emitting pass — `decompose_simple_command` (command word / assignment-prefix value), `push_embedded_units_from_structural_words` (assignment value, `for` word, `case` subject/pattern), `push_embedded_units_from_redirect_targets` (redirect target) — from the AST node each already holds.

## 2. Annotate from the carried origin

- [ ] 2.1 Write a failing engine test: the motivating script's reason annotation describes the assignment to `dest` and does not contain `in `set``.
- [ ] 2.2 Rewrite `annotate_embedded_reason` to consume the carried `SubstitutionOrigin` (producing the per-kind labels: ``in `c```, ``in assignment to `v```, ``in `for` list``, ``in `case` subject``, `in redirect target`). Delete `outer_command_name` and its global first-simple-command scan.

## 3. Spec scenarios & regression

- [ ] 3.1 Add engine tests for the three spec scenarios (assignment target named, simple command named, redirect target described) plus the `in `set`` cross-attribution regression.
- [ ] 3.2 Update any existing snapshot tests asserting the old `in <first-command>` suffix.

## 4. Coverage

- [ ] 4.1 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered origin-kind branches.
- [ ] 4.2 Check in any new `proptest-regressions/` files.
- [ ] 4.3 Review REFERENCE.md: if it documents substitution-origin reason annotations, update the example labels to the new per-position forms; otherwise record "verified, no surface change".

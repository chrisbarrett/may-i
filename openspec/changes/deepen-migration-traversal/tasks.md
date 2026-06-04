## 1. Parity oracle (red first)

- [ ] 1.1 Add a characterization test that serializes `migrate()` output for every form in `examples/*.lisp` and snapshots it; this is the byte-identical parity oracle for the refactor.
- [ ] 1.2 Add a generated v1 corpus to the snapshot using the existing `any_v1_*` proptest generators, capturing pre-refactor `migrate()` output as the baseline.

## 2. Traversal seam in `sexpr`

- [ ] 2.1 Promote `ShapeF::map`, `CstNode::map`, `CstNode::fold` out of `#[cfg(test)]` to the narrowest production visibility that compiles (`crates/sexpr/src/cst.rs`).
- [ ] 2.2 Write failing proptests for a new post-order rewrite combinator: post-order coverage (every node offered), termination within `MAX_ITERS`, and idempotence on already-canonical input.
- [ ] 2.3 Implement the post-order (bottom-up) rewrite combinator over the `ShapeF`/`CstNode` functor, driving convergence with the same restart discipline as `rewrite_until_convergence`; keep `transform` for its existing callers.
- [ ] 2.4 Write a failing trivia round-trip proptest (comment survival; sentinel `Span::new(0,1)` for comment-only nodes; zero-span reflow).
- [ ] 2.5 Move trivia preservation into the seam (re-graft source trivia vs reflow constructed nodes, keyed on `has_source_trivia`); fold in the `strip_whitespace_trivia` rule.

## 3. Cut migration over to the seam

- [ ] 3.1 Point `migrate()` (`crates/config/src/migrate/mod.rs`) at the new combinator; confirm the §1 snapshot and the `migration-system` property/regression suites stay green.

## 4. Simplify passes (one at a time, snapshot-guarded)

- [ ] 4.1 Refactor the full-recursion passes (`effect_to_decision_verb`, `check_form`, `flatten_nested_if`) to local rewrites — remove internal recursion; verify snapshot parity after each.
- [ ] 4.2 Refactor remaining passes that hand-thread trivia (`simplify_command`, `flag_patterns`, and any other `strip_whitespace_trivia` callers) to rely on the seam; verify snapshot parity after each.
- [ ] 4.3 Audit the remaining passes in `migration_rules()` for residual recursion/trivia bookkeeping and simplify; preserve registry order and documented ordering constraints.
- [ ] 4.4 Remove now-dead `helpers.rs` paths; confirm no production pass re-implements node recursion.

## 5. Verification

- [ ] 5.1 Run the full test suite including `migrate/property_tests.rs` and `regression_tests.rs`; confirm byte-identical migration output via the §1 snapshot.
- [ ] 5.2 Run `cargo fmt`, `cargo clippy` (workspace lints incl. `unreachable_pub`), and `cargo tarpaulin`; inspect `lcov.info` for uncovered seam branches.
- [ ] 5.3 Run `openspec validate deepen-migration-traversal` and `scripts/validate-spec-frontmatter.sh`; confirm the change is apply-clean and the new spec frontmatter passes.

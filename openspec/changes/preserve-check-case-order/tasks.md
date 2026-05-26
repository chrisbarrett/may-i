## 1. Canonicaliser change

- [ ] 1.1 Remove the `Some("check") => sort_check_body` arm from `canonicalise_node` in `crates/config/src/canonicalise.rs`
- [ ] 1.2 Delete `sort_check_body` and `check_case_sort_key` (now dead) from the same file
- [ ] 1.3 Update the module-level doc comment (lines 8-22) to reflect the new "sort only when engine-order-independent AND not human-curated" principle; remove the bullet claiming `(check …)` cases are alphabetised

## 2. Tests

- [ ] 2.1 Rename unit test `check_cases_alphabetised_by_command` to `check_cases_preserve_source_order`; assert that `(check (deny "rm -rf /") (allow "ls"))` renders unchanged
- [ ] 2.2 Add a unit test asserting that a `(check …)` form with interleaved `;;` section-header comments preserves the comment-to-case adjacency under canonicalisation
- [ ] 2.3 Keep the `canonicalise_is_idempotent_on_check` proptest as-is; it now guards against re-introduction of any non-idempotent rewrite to check bodies

## 3. Documentation

- [ ] 3.1 Update `REFERENCE.md` lines 757 and 862: replace "(check …) body: cases alphabetised by command string" with "(check …) body: source order preserved"
- [ ] 3.2 Verify `CONTEXT.md` § "Canonical-form ordering" matches the new behaviour (already updated during exploration — confirm no drift)

## 4. Verification

- [ ] 4.1 Run `cargo fmt` and `cargo build --workspace`
- [ ] 4.2 Run `cargo test --workspace`; confirm the renamed and added unit tests pass and the idempotence proptest still holds
- [ ] 4.3 Run `cargo tarpaulin`; inspect `lcov.info` for any new uncovered branches in `canonicalise.rs`
- [ ] 4.4 Run `may-i fmt` on `~/.config/nix-configuration/home/config/programs/may-i/rules/terragrunt-terraform-tofu.lisp` and confirm authored check-case order is preserved (note: existing alphabetised ordering won't auto-regroup — that's expected)
- [ ] 4.5 Run `openspec validate preserve-check-case-order` to confirm the change still validates

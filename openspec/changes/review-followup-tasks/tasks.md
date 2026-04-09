## 1. Migration regression tests (from migration-regression-tests change)

- [ ] 1.1 Add test: `has` with compound value pattern `(has [:key (and (regex "^prod-") (not "prod-test"))])` in `regression_tests.rs`
- [ ] 1.2 Add test: `(command (or "cat" "head" "tail"))` multi-element or in `regression_tests.rs`
- [ ] 1.3 Add test: inline comments inside wrapper forms preserved in `regression_tests.rs`
- [ ] 1.4 Add `any_v1_wrapper` proptest generator in `property_tests.rs`
- [ ] 1.5 Add `any_v1_config` proptest generator (mixing all form types) in `property_tests.rs`
- [ ] 1.6 Add eval-equivalence property tests for the new wrapper and config generators

## 2. Positional backtracking proptests (from add-missing-proptests change)

- [ ] 2.1 Add proptest to `crates/engine/src/eval/positional.rs`: matched + unconsumed = original args
- [ ] 2.2 Add property: ZeroOrMore is greedy (maximal match)
- [ ] 2.3 Add property: matching is deterministic

## 3. Config parse roundtrip proptest fix (from add-missing-proptests change)

- [ ] 3.1 Fix config roundtrip proptest in `crates/config/src/config.rs` to include serialize step: parse → serialize → re-parse → compare

## 4. Integration test gaps (from add-integration-tests change)

- [ ] 4.1 Add test: `MAYI_CONFIG` env var pointing to nonexistent path produces descriptive error
- [ ] 4.2 Strengthen `migrate_v2_config_outputs_unchanged` to assert "no changes" or unchanged output explicitly

## 5. Test cleanup (from test-suite-cleanup change)

- [ ] 5.1 Remove or replace struct-construction tests from `tests/migration_diff.rs` (lines ~120-173)

## 6. API surface (from tighten-api-surface change)

- [ ] 6.1 Change `Ann` enum to `pub(crate)` in `src/annotation.rs`, or document why it must stay `pub`

## 7. Update archived task files

- [ ] 7.1 Check off all completed items in the 5 affected archived task files

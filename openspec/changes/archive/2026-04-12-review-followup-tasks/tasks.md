## 1. Migration regression tests (from migration-regression-tests change)

- [x] 1.1 Add test: `has` with compound value pattern `(has [:key (and (regex "^prod-") (not "prod-test"))])` in `regression_tests.rs`
- [x] 1.2 Add test: `(command (or "cat" "head" "tail"))` multi-element or in `regression_tests.rs`
- [x] 1.3 Add test: inline comments inside wrapper forms preserved in `regression_tests.rs`
- [x] 1.4 Add `any_v1_wrapper` proptest generator in `property_tests.rs`
- [x] 1.5 Add `any_v1_config` proptest generator (mixing all form types) in `property_tests.rs`
- [x] 1.6 Add eval-equivalence property tests for the new wrapper and config generators

## 2. Positional backtracking proptests (from add-missing-proptests change)

- [x] 2.1 Add proptest to `crates/engine/src/eval/positional.rs`: matched + unconsumed = original args
- [x] 2.2 Add property: ZeroOrMore is greedy (maximal match)
- [x] 2.3 Add property: matching is deterministic

## 3. Config parse roundtrip proptest fix (from add-missing-proptests change)

- [x] 3.1 Fix config roundtrip proptest in `crates/config/src/config.rs` to include serialize step: parse → serialize → re-parse → compare

## 4. Integration test gaps (from add-integration-tests change)

- [x] 4.1 Add test: `MAYI_CONFIG` env var pointing to nonexistent path produces descriptive error
- [x] 4.2 Strengthen `migrate_v2_config_outputs_unchanged` to assert "no changes" or unchanged output explicitly

## 5. Test cleanup (from test-suite-cleanup change)

- [x] 5.1 Remove or replace struct-construction tests from `tests/migration_diff.rs` (lines ~120-173)

## 6. API surface (from tighten-api-surface change)

- [x] 6.1 Change `Ann` enum to `pub(crate)` in `src/annotation.rs`, or document why it must stay `pub`

## 7. Update archived task files

- [x] 7.1 Check off all completed items in the 5 affected archived task files

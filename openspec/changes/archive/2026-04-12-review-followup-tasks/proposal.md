## Why

Pre-release code review produced 8 changes, 7 of which were implemented by worktree agents. Assessment found 14 tasks across 5 changes that were skipped or only partially completed. These need to be finished to close out the review.

## What Changes

- Add 4 missing migration regression tests (compound has, multi-element or, inline wrapper comments)
- Add 3 missing positional backtracking proptests
- Fix config parse roundtrip proptest to include a serialize step
- Add 3 missing proptest generators (v1 wrapper, v1 config, eval-equivalence for those)
- Add 2 missing integration tests (MAYI_CONFIG env var error, migrate "no changes" assertion)
- Remove struct-construction tests from migration_diff.rs
- Change `Ann` enum to `pub(crate)` if feasible

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `crates/config/src/migrate/regression_tests.rs` — new tests
- `crates/config/src/migrate/property_tests.rs` — new generators + proptests
- `crates/config/src/config.rs` — fix roundtrip proptest
- `crates/engine/src/eval/positional.rs` — new proptests
- `tests/migration_diff.rs` — remove dead tests
- `tests/migrate_integration.rs` — strengthen assertion
- `tests/hook_integration.rs` or `tests/eval_stdin.rs` — MAYI_CONFIG error test
- `src/annotation.rs` — visibility change

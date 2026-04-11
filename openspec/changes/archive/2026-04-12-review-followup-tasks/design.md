## Context

14 tasks remain from the pre-release review. All are small, independent items — tests to add, a proptest to fix, dead tests to remove, and one visibility change. No architectural decisions needed.

## Goals / Non-Goals

**Goals:** Complete all 14 remaining items. Check off tasks in the archived changes once verified.

**Non-Goals:** No new review findings. No refactoring beyond what was already scoped.

## Decisions

### Group by file locality, not by original change
The 14 items span 5 archived changes but map to ~6 files. Group by file to minimize context switches.

### Ann pub(crate) — investigate before changing
The agent left `Ann` as `pub` because integration tests reference it through `evaluate_segments`. Check if the type can be made `pub(crate)` by adjusting the test API, or drop the task.

### Positional proptests — new test module
`crates/engine/src/eval/positional.rs` has no test module. Create one with the 3 property tests.

## Risks / Trade-offs

- None significant. All items are additive tests or minor cleanups.

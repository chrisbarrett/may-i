## Context

Three bugs were found during pre-release code review. All are straightforward fixes with clear root causes and no architectural implications.

## Goals / Non-Goals

**Goals:**
- Fix Unicode width miscalculation in layout rendering
- Eliminate production panic path in check evaluation
- Remove debug output leak in pp renderer

**Non-Goals:**
- Refactoring the layout or check systems beyond the bug fixes

## Decisions

### Use `may_i_pp::visible_len` for heading width
NoteHeading and ColRow currently use `s.len()` (byte length). The pp crate already has `visible_len()` that handles ANSI and Unicode. Use it directly rather than `chars().count()` since the layout crate already depends on pp.

### Propagate EvalError from check evaluation
`check.rs:67` calls `evaluate().unwrap()`. Replace with `?` to propagate the error. The caller `run_checks()` returns `Vec<CheckResult>` — convert evaluation errors into a CheckResult with an appropriate diagnostic message rather than changing the return type.

### Remove the entire debug_assertions block
The `eprintln!` for "forbidden" forms is debug scaffolding. Remove the entire `#[cfg(debug_assertions)]` block, not just the print — the conditional check serves no purpose without the output.

## Risks / Trade-offs

- [NoteHeading fix may shift column alignment in existing output] → Acceptable — current output is wrong for Unicode. Snapshot tests will catch any unexpected shifts.
- [Check error propagation changes behavior for UnresolvedPredicate] → Previously panicked, now reports a diagnostic — strictly better.

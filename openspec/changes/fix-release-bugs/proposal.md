## Why

Pre-release code review found three bugs that affect correctness or user experience: a Unicode width miscalculation in layout rendering, an unwrap that can panic in production, and a debug print that leaks to stderr.

## What Changes

- Fix `NoteHeading::from(String)` to use visible width instead of byte length — currently miscalculates column alignment for Unicode headings (ℹ, ⚠, ✗)
- Fix same bug in `ColRow::kv` label width calculation
- Replace production `unwrap()` in `crates/engine/src/check.rs:67` with proper error propagation — `evaluate()` can return `Err(UnresolvedPredicate)` which panics at runtime
- Remove debug `eprintln!` in `crates/pp/src/render/mod.rs:166-167` that prints "render_list: forbidden using render_flat" in debug builds

## Capabilities

### New Capabilities

### Modified Capabilities

- `unified-renderer`: Fix NoteHeading and ColRow width calculations to handle Unicode correctly
- `evaluator-error-handling`: Propagate evaluation errors from check instead of panicking

## Impact

- `crates/layout/src/lib.rs` — NoteHeading::from, ColRow::kv
- `crates/engine/src/check.rs` — evaluate() call site
- `crates/pp/src/render/mod.rs` — remove debug_assertions block

## Why

Several source files have grown beyond 1000 lines of implementation code,
making them hard to navigate, test in isolation, and review. The `pp` crate is a
single 3242-line file with 5 interleaved `#[cfg(test)]` blocks; `engine/eval.rs`
mixes entry points, predicate evaluation, positional backtracking, and effect
evaluation in one file; and `engine/test_generators.rs` has 165 lines of
generators buried under 1600 lines of inline tests that repeat imports.

## What Changes

- Split `crates/pp/src/lib.rs` (3242 lines) into ~4 modules: output traits,
  rendering engine, colorization/helpers, and format/detection.
- Split `crates/engine/src/eval.rs` (2911 lines) into ~4 modules: entry
  points/context, predicate evaluation, positional pattern matching, and effect
  evaluation.
- Extract inline test modules from `crates/engine/src/test_generators.rs` (1766
  lines) into separate test files, leaving only the 165 lines of generators.
- All public API paths remain unchanged via re-exports from `mod.rs`/`lib.rs`.

## Capabilities

### New Capabilities

### Modified Capabilities
- `module-structure`: Applying the existing module-structure spec to the three
  largest offending files identified by line-count analysis.

## Impact

- `crates/pp/src/` — `lib.rs` replaced by `lib.rs` + submodules
- `crates/engine/src/` — `eval.rs` replaced by `eval/` directory;
  `test_generators.rs` slimmed with tests moved to separate files
- No public API changes — all re-exports preserve existing import paths
- No functional changes — pure restructuring

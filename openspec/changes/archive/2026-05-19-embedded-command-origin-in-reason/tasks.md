## 1. Carry substitution form through decompose

- [x] 1.1 Add `EmbeddedKind { Backtick, Dollar }` enum in `crates/engine/src/eval/decompose.rs`
- [x] 1.2 Extend `EvalUnit::EmbeddedCommand` with a `kind: EmbeddedKind` field
- [x] 1.3 Update `push_embedded_units_from_word` to read the `WordPart` discriminant and populate `kind`
- [x] 1.4 Update existing decompose tests (`decompose_command_substitution_in_arg`, `decompose_substitution_as_command_name`) to assert the new field

## 2. Annotate aggregate reason at the embedded callsite

- [x] 2.1 In `evaluate_command_inner` (`crates/engine/src/eval/command.rs`), capture the outer command name from the first `SimpleCommand` unit before the per-unit loop
- [x] 2.2 When an `EmbeddedCommand` unit's result becomes the new `aggregate_reason`, wrap the inner reason with `({kind} substitution in `{outer}`)`
- [x] 2.3 Implement the double-wrap guard: skip wrapping when the inner reason already contains ` substitution in `
- [x] 2.4 Handle the dynamic-outer case (first unit is `DynamicCommand`): fall back to `(embedded substitution)` with no outer name

## 3. Tests

- [x] 3.1 Add unit tests in `crates/engine/src/eval/command.rs` for each scenario in the rule-decisions delta spec (backtick, `$(…)`, top-level unchanged, nested no double-wrap)
- [x] 3.2 Add a regression test for the original bug: ``grep -nE "x|`:rebuild`y" file``
- [x] 3.3 Add a property test asserting the reason never contains a literal `\n` — covered by existing `prop_reason_is_single_line` (the `arb_shell_chars` strategy exercises `$`/backtick embedded paths)
- [x] 3.4 Refresh any snapshot tests under `tests/snapshots/` and `src/snapshots/` that capture embedded-substitution reasons — none exist (verified `rg` over the snapshot dirs)

## 4. Verify and document

- [x] 4.1 Run `cargo fmt`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`
- [x] 4.2 Run `cargo tarpaulin` and check `lcov.info` for uncovered branches in the new annotation path; add proptests or surgical unit tests as needed — all branches of `annotate_embedded_reason` (lines 23-35) and `kind_from_form` (lines 16-20) executed
- [x] 4.3 Run `openspec validate embedded-command-origin-in-reason --strict`

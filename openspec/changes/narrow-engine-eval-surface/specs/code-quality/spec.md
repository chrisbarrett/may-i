## ADDED Requirements

### Requirement: Engine crate public surface is bounded

The `may-i-engine` crate SHALL export only items that have at least one consumer outside the crate. The supported `eval` surface comprises `Evaluator`, `EvalContext`, `PredicateResult`, `evaluate`, `evaluate_with_fold`, `evaluate_command`, and `evaluate_command_with_fold`. The crate-level surface additionally comprises `EvalResult`, `SegmentDecision`, `EvalError`, the `check` module, the `trust` module, and the `fold` module's `EvalFold`, `ChildResult`, and `PureFold` items.

Items not listed above SHALL be `pub(crate)` or narrower. Re-exports for items that lack an external caller SHALL NOT exist in `crates/engine/src/eval/mod.rs` or `crates/engine/src/lib.rs`.

#### Scenario: Demoted re-exports are crate-private

- **WHEN** `crates/engine/src/eval/mod.rs` is inspected
- **THEN** `BindingValue`, `Bindings`, `parse_argv`, `EvalUnit`, `decompose`, `parser_positional_args`, and `tokenise` SHALL NOT appear in a `pub use` statement

#### Scenario: Documented surface compiles in isolation

- **WHEN** `cargo check --workspace` runs against the workspace after the visibility change
- **THEN** the build SHALL succeed without any consumer reaching for a demoted item

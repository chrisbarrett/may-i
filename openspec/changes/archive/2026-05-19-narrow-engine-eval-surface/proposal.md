## Why

`crates/engine/src/eval/mod.rs` re-exports 14 items, but seven of them — `BindingValue`, `Bindings`, `parse_argv`, `EvalUnit`, `decompose`, `parser_positional_args`, `tokenise` — have zero callers outside the engine crate. The wide seam means internal restructuring (renaming a binding type, splitting `decompose`, re-shaping the tokeniser) is a breaking change for the workspace even though no consumer depends on the leaked types. The engine's effective contract is much narrower than its declared surface.

## What Changes

- **BREAKING** (workspace-internal only): Demote unused `eval` re-exports to `pub(crate)`. The targets are `BindingValue`, `Bindings`, `parse_argv`, `EvalUnit`, `decompose`, `parser_positional_args`, `tokenise`.
- Keep public: `Evaluator`, `EvalContext`, `PredicateResult`, `evaluate`, `evaluate_with_fold`, `evaluate_command`, `evaluate_command_with_fold`. These have grep-verified external callers (CLI binary, integration tests, `src/annotation.rs`).
- Document the remaining surface in `crates/engine/src/lib.rs` so future re-exports are deliberate.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `code-quality`: add a contributor invariant pinning the engine crate's public surface so the narrowed seam is a checked rule, not a one-time edit.

## Impact

- Affected code: `crates/engine/src/eval/mod.rs`, `crates/engine/src/lib.rs`. No call-site changes expected — verified by grep.
- Affected specs: `code-quality` (delta).
- Risk: low. Pre-1.0 project; back-compat is not required. If any forgotten caller exists, the compiler reports it immediately.

## Why

Several public types and functions are wider than necessary. Key enums lack `#[non_exhaustive]`, meaning any variant addition is a breaking change for downstream consumers. Internal implementation details are exposed as `pub` when `pub(crate)` suffices.

## What Changes

- Add `#[non_exhaustive]` to `Effect`, `Predicate`, `EvalError`, `FactPattern`, `Expr<E>`, `CommandPattern`, `ArgPattern`
- Restrict `ParsedCheck` and `parse_check_command()` to `pub(crate)` in engine crate
- Restrict `Ann` enum and `TracingFold` struct to `pub(crate)` in binary crate
- Restrict `print_separator`, `render_elements` to `pub(crate)` in output module
- Make `ResolutionError` fields private (add accessors) or add `#[non_exhaustive]`

## Capabilities

### New Capabilities

### Modified Capabilities

- `configuration-language`: Add `#[non_exhaustive]` to AST enums
- `eval-fold-trait`: Restrict engine-internal types to pub(crate)

## Impact

- `crates/core/src/ast.rs`, `crates/core/src/pattern.rs`, `crates/core/src/predicates.rs` — non_exhaustive attrs
- `crates/engine/src/check.rs`, `crates/engine/src/lib.rs` — visibility restrictions
- `src/annotation.rs`, `src/output/mod.rs` — pub(crate) changes
- `crates/config/src/resolve.rs` — ResolutionError encapsulation

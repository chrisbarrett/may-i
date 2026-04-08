## Context

Public enums in core/engine will break downstream exhaustive matches when variants are added. Several internal types are unnecessarily pub.

## Goals / Non-Goals

**Goals:**
- Prevent future breaking changes from enum variant additions
- Minimize public API to intentional surface only

**Non-Goals:**
- Changing any behavior — purely visibility/attribute changes
- Adding #[non_exhaustive] to types that are genuinely closed (e.g., Decision)

## Decisions

### Add #[non_exhaustive] to extensible enums only
Apply to: Effect, Predicate, EvalError, FactPattern, Expr<E>, CommandPattern, ArgPattern. These are likely to gain variants as the language evolves. Do NOT apply to Decision (Allow/Deny/Ask is a closed set) or EffectResult.

### Use pub(crate) not pub(super)
For items only used within a crate, use `pub(crate)` consistently rather than mixing `pub(super)` and `pub(crate)`.

### ResolutionError: add #[non_exhaustive] not private fields
Making fields private would require adding accessor methods — more churn than benefit. Use `#[non_exhaustive]` to prevent external construction while keeping field access.

## Risks / Trade-offs

- [#[non_exhaustive] forces wildcard arms in downstream matches] → Intentional — downstream code should handle unknown variants gracefully.
- [pub(crate) changes could break integration tests] → Integration tests use the binary crate's public API (evaluate_segments, write_eval_output), which remains pub.

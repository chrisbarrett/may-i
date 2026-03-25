## Context

The current `Expr<E>` type in `crates/core/src/types.rs` uses a simple generic parameter to carry effects in `Cond` branches. While this works, it doesn't enable powerful generic traversals that would be possible with a proper fixpoint-of-functor pattern.

Looking at the CST (Concrete Syntax Tree) implementation in `crates/sexpr/src/cst.rs`, we see the proper pattern:
- `ShapeF<R>` is the base functor with a type parameter for recursive children
- `CstNode<A>` is the fixpoint: `CstNode<A> = ShapeF<Box<CstNode<A>>>` with annotation A
- Functor operations (`map`, `map_ref`, `map_ref_mut`) enable generic transformations

The CST pattern allows for elegant generic traversals without boilerplate. Applying this same pattern to `Expr` will enable similar capabilities for expression manipulation.

## Goals / Non-Goals

**Goals:**
- Refactor `Expr` to use the fixpoint-of-functor pattern
- Enable generic traversals (catamorphisms/anamorphisms) over expressions
- Maintain backward compatibility where possible
- Support both old `Effect` and new `V2Effect` types cleanly
- Update all dependent code (parser, evaluator, patterns)

**Non-Goals:**
- Full migration to new effect types (old `Effect` still supported)
- Optimization of expression evaluation
- Adding new expression types beyond what's needed for refactoring

## Decisions

### Decision: Use base functor with phantom type marker

We'll introduce `ExprF<R, E>` as the base functor where:
- `R` is the recursive child type (will be `Box<Expr<E>>` in the fixpoint)
- `E` is the effect type carried in `Cond` branches

**Rationale:** This is the standard fixpoint pattern used in functional programming and seen in the CST implementation. It cleanly separates the shape of the data from the recursion.

**Alternatives considered:**
- Keep current generic approach: Doesn't enable generic traversals
- Use GADTs: More complex, harder to understand
- Separate expression types for each effect: Code duplication

### Decision: Keep effect type explicit in functor

The functor will carry the effect type `E` explicitly, not as a phantom type.

**Rationale:** This allows `Cond` branches to hold effects of type `E` directly, which is the main use case for the generic parameter.

**Trade-off:** Less flexibility than a fully phantom type, but simpler and meets our needs.

### Decision: Implement functor operations as methods

Implement `map`, `map_ref`, and `map_ref_mut` as methods on `ExprF<R, E>`.

**Rationale:** Consistent with the CST implementation and enables the traversal patterns we need.

**Pattern:**
```rust
impl<R, E> ExprF<R, E> {
    pub fn map<S>(self, f: impl FnMut(R) -> S) -> ExprF<S, E> { ... }
    pub fn map_ref<S>(&self, f: impl FnMut(&R) -> S) -> ExprF<S, E> { ... }
}
```

### Decision: Type alias for backward compatibility

Provide `type Expr<E = Effect> = ExprF<Box<ExprF<...>>, E>` as the public type.

**Rationale:** Allows existing code to continue using `Expr<Effect>` with minimal changes.

**Migration path:** Update uses gradually, add type annotations where inference fails.

## Risks / Trade-offs

**Risk:** Breaking changes to existing code that constructs `Expr` directly
→ **Mitigation:** Provide clear migration guide, use type aliases, update tests incrementally

**Risk:** Performance overhead from additional boxing in fixpoint
→ **Mitigation:** Use `Box<Expr<E>>` consistently, benchmark to ensure no regression

**Risk:** Complexity increase for developers unfamiliar with fixpoint pattern
→ **Mitigation:** Document pattern clearly, provide examples, keep API simple

**Risk:** Type inference failures in tests and complex code
→ **Mitigation:** Add explicit type annotations where needed, use turbofish syntax

## Migration Plan

1. **Phase 1: Core refactor**
   - Define `ExprF<R, E>` base functor in `types.rs`
   - Implement functor operations
   - Create `Expr<E>` fixpoint type alias

2. **Phase 2: Update pattern types**
   - Update `ArgPattern`, `PositionalArg` to use `Expr<V2Effect>`
   - Update v2 pattern module types

3. **Phase 3: Update parser**
   - Modify pattern parsers to return `Expr<Effect>`
   - Add explicit type annotations where needed

4. **Phase 4: Update evaluator**
   - Refactor engine to use `Expr<V2Effect>`
   - Update annotation module for new types

5. **Phase 5: Fix tests**
   - Add type annotations in test code
   - Fix any remaining compilation errors

6. **Phase 6: Cleanup**
   - Remove unused imports
   - Verify all tests pass
   - Update documentation

## Open Questions

1. Should we provide a `cata` (catamorphism) function as part of this change, or leave it for future work?
2. How should we handle the `Cond` variant's `Vec<ExprBranch<E>>` in the fixpoint - keep as Vec or use something else?
3. Do we need to update the `ExprBranch` struct as well, or can it remain as-is?

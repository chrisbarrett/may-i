## Why

The current `Expr<E>` type is generic but doesn't follow the fixpoint-of-functor pattern, limiting our ability to write generic traversals and transformations. By refactoring `Expr` to use a base functor with a fixpoint (similar to how `CstNode` works in the sexpr crate), we enable powerful generic operations like catamorphisms and anamorphisms for expression manipulation, analysis, and pretty-printing.

## What Changes

- **Refactor `Expr` to use functor/fixpoint pattern**: Introduce `ExprF<R>` as the base functor and `Expr<E>` as the fixpoint, enabling generic recursive traversals.
- **Add functor operations**: Implement `map`, `map_ref`, and `map_ref_mut` for the base functor.
- **Update pattern types**: Migrate `ArgPattern`, `PositionalArg`, and related types to use the new fixpoint representation.
- **Update parser**: Modify pattern parsers in `crates/config/src/v2/pattern.rs` to work with the new types.
- **Update evaluator**: Refactor engine and annotation modules to use `Expr<V2Effect>` instead of the current ad-hoc generic approach.
- **Fix test type annotations**: Add explicit type annotations in tests where type inference fails.
- **Clean up unused imports**: Remove unused imports introduced during the generic refactor.

## Capabilities

### New Capabilities
- `expr-functor`: Expression type using fixpoint-of-functor pattern for generic traversals

### Modified Capabilities
- `partial-pattern-matching`: Update pattern types to use new Expr fixpoint representation
- `unified-effect-evaluation`: Update evaluator to work with Expr<V2Effect>

## Impact

- `crates/core/src/types.rs`: Major refactor of Expr and related types
- `crates/core/src/v2/pattern.rs`: Update pattern types to use new Expr representation
- `crates/config/src/v2/pattern.rs`: Update parser for new types
- `crates/engine/src/v2/eval.rs`: Update evaluator for new types
- `crates/engine/src/annotate.rs`: Update annotation generation for new types
- Test files throughout: Add type annotations for generic Expr<E>

## Breaking Changes

**BREAKING**: The `Expr` type becomes a fixpoint-of-functor, changing how it's constructed and pattern-matched. Existing code constructing `Expr` directly will need updates.

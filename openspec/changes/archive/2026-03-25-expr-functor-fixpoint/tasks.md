## 1. Core Type Refactor

- [x] 1.1 Define `ExprF<R, E>` base functor enum in `crates/core/src/types.rs`
- [x] 1.2 Implement `map` operation for `ExprF<R, E>`
- [x] 1.3 Implement `map_ref` operation for `ExprF<R, E>`
- [x] 1.4 Implement `map_ref_mut` operation for `ExprF<R, E>`
- [x] 1.5 Create `Expr<E>` fixpoint type alias
- [x] 1.6 Update `ExprBranch<E>` to work with new functor pattern
- [x] 1.7 Ensure `ToDoc` trait works with new types

## 2. Pattern Type Updates

- [x] 2.1 Update `PositionalArg` to use `Expr<Effect>` for pattern field
- [x] 2.2 Update `ArgPattern::Anywhere` to use `Vec<Expr<Effect>>`
- [x] 2.3 Update `ArgPattern::Forbidden` to use `Vec<Expr<Effect>>`
- [x] 2.4 Update `ArgPattern::At` to use `Expr<Effect>` for pattern field
- [x] 2.5 Update constructor functions (`PositionalArg::one`, `with_quantifier`)
- [x] 2.6 Update `ArgPattern` constructors to use new types

## 3. Parser Updates

- [x] 3.1 Update `parse_expr` in config pattern parser to return `Expr<Effect>`
- [x] 3.2 Update cond branch parsing to work with `ExprBranch<Effect>`
- [x] 3.3 Fix type annotations in pattern parser for generic `Expr<E>`
- [x] 3.4 Ensure wildcard `*` parsing works with new types
- [x] 3.5 Ensure regex, or, and, not expression parsing works

## 4. Engine Updates

- [x] 4.1 Update `match_expr` function signature to accept `Expr<V2Effect>`
- [x] 4.2 Update pattern matching logic for new `Expr` representation
- [x] 4.3 Update `ArgPattern` evaluation to handle `Expr<V2Effect>`
- [x] 4.4 Update `PositionalArg` evaluation for new types
- [x] 4.5 Ensure recursive evaluation still works correctly

## 5. Annotation Updates

- [x] 5.1 Update `find_effect` calls to work with new `Expr` type
- [x] 5.2 Fix type inference issues in annotate module
- [x] 5.3 Update `Expr` handling in annotation generation
- [x] 5.4 Ensure trace output format is preserved

## 6. Test Fixes

- [x] 6.1 Add type annotations in core types tests for `Expr<Effect>`
- [x] 6.2 Fix pattern matching tests with new type signatures
- [x] 6.3 Update engine tests for new `Expr` representation
- [x] 6.4 Update annotation tests for type annotations
- [x] 6.5 Ensure all existing tests still pass

## 7. Cleanup

- [x] 7.1 Remove unused imports in core crate
- [x] 7.2 Remove unused imports in config crate
- [x] 7.3 Remove unused imports in engine crate
- [x] 7.4 Run clippy and fix warnings
- [x] 7.5 Run cargo fmt on all changes
- [x] 7.6 Verify no compilation warnings remain

## 8. Documentation

- [x] 8.1 Update module-level documentation for new types
- [x] 8.2 Add examples of functor operations in doc comments
- [x] 8.3 Document migration path for existing code
- [x] 8.4 Update README if needed

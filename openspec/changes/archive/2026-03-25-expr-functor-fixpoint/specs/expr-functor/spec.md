## ADDED Requirements

### Requirement: Expr uses base functor pattern
The `Expr` type SHALL be implemented as a fixpoint of a base functor `ExprF<R, E>`.

#### Scenario: Base functor defined
- **WHEN** examining the `Expr` type definition
- **THEN** it SHALL use `ExprF<Box<Expr<E>>, E>` as its representation

#### Scenario: Fixpoint type alias provided
- **WHEN** using the `Expr<E>` type alias
- **THEN** it SHALL resolve to the fixpoint of `ExprF` with effect type `E`

### Requirement: Functor implements map operations
The `ExprF<R, E>` base functor SHALL implement `map`, `map_ref`, and `map_ref_mut` operations.

#### Scenario: Map transforms children
- **GIVEN** an `ExprF<R, E>` with recursive children of type `R`
- **WHEN** calling `map` with a function `f: R -> S`
- **THEN** it SHALL return `ExprF<S, E>` with transformed children

#### Scenario: Map_ref transforms by reference
- **GIVEN** an `ExprF<R, E>` with recursive children
- **WHEN** calling `map_ref` with a function `f: &R -> S`
- **THEN** it SHALL return `ExprF<S, E>` without consuming self

#### Scenario: Map_ref_mut transforms by mutable reference
- **GIVEN** an `ExprF<R, E>` with recursive children
- **WHEN** calling `map_ref_mut` with a function `f: &mut R -> S`
- **THEN** it SHALL return `ExprF<S, E>` using mutable access

### Requirement: Effect type preserved in functor
The effect type parameter `E` SHALL be preserved through all functor operations.

#### Scenario: Map preserves effect type
- **GIVEN** an `ExprF<R, Effect>` carrying effects of type `Effect`
- **WHEN** calling `map` to transform children
- **THEN** the resulting `ExprF<S, Effect>` SHALL still carry effects of type `Effect`

#### Scenario: Cond branches hold effects
- **GIVEN** an `ExprF` with a `Cond` variant containing branches
- **WHEN** examining the branches
- **THEN** each branch SHALL hold an effect of type `E`

### Requirement: Backward compatibility maintained
The refactored `Expr<E>` SHALL remain backward compatible with existing usage patterns.

#### Scenario: Existing pattern matching works
- **GIVEN** existing code that pattern matches on `Expr<Effect>`
- **WHEN** compiling with the refactored type
- **THEN** pattern matching SHALL continue to work without modification

#### Scenario: Type inference preserved
- **GIVEN** code that relies on type inference for `Expr<Effect>`
- **WHEN** compiling with the refactored type
- **THEN** type inference SHALL succeed in most cases (some annotations may be needed in complex scenarios)

## MODIFIED Requirements

### Requirement: PositionalArg uses Expr with effect type
`PositionalArg` SHALL use `Expr<Effect>` for its pattern field instead of bare `Expr`.

#### Scenario: Pattern field is typed
- **WHEN** examining a `PositionalArg` struct
- **THEN** its `pattern` field SHALL have type `Expr<Effect>`

#### Scenario: PositionalArg construction works
- **GIVEN** a valid expression of type `Expr<Effect>`
- **WHEN** constructing a `PositionalArg::one(expr)`
- **THEN** it SHALL create a valid `PositionalArg` instance

### Requirement: ArgPattern uses Expr with effect type
`ArgPattern` SHALL use `Expr<Effect>` for its expression fields.

#### Scenario: Anywhere pattern uses typed expressions
- **WHEN** examining an `ArgPattern::Anywhere` variant
- **THEN** it SHALL contain `Vec<Expr<Effect>>` instead of `Vec<Expr>`

#### Scenario: Forbidden pattern uses typed expressions
- **WHEN** examining an `ArgPattern::Forbidden` variant
- **THEN** it SHALL contain `Vec<Expr<Effect>>` instead of `Vec<Expr>`

#### Scenario: At position pattern uses typed expression
- **WHEN** examining an `ArgPattern::At` variant
- **THEN** its `pattern` field SHALL have type `Expr<Effect>`

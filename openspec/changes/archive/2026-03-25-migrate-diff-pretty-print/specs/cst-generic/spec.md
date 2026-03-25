## ADDED Requirements

### Requirement: CST implements fixpoint of functor pattern
The CST SHALL be refactored to use a fixpoint-of-functor pattern, enabling generic annotations on nodes.

#### Scenario: Functor map transforms annotations
- **WHEN** a `CstNode<A>` exists with annotation type A
- **THEN** calling `map` with a function `A -> B` SHALL produce a `CstNode<B>`
- **AND** the tree structure SHALL be preserved unchanged

#### Scenario: Catamorphism enables bottom-up traversal
- **WHEN** folding over a `CstNode<A>` with an algebra `F<B> -> B`
- **THEN** children SHALL be reduced before parents
- **AND** the algebra SHALL receive reduced children and the annotation

### Requirement: ShapeF provides base functor operations
`ShapeF<R>` SHALL implement functor operations for mapping over recursive positions.

#### Scenario: Map transforms children
- **WHEN** calling `map` on `ShapeF::List(children)`
- **THEN** the function SHALL be applied to each child
- **AND** the result SHALL be `ShapeF::List(transformed_children)`

#### Scenario: Map preserves atoms
- **WHEN** calling `map` on `ShapeF::Atom(s)`
- **THEN** the atom SHALL be returned unchanged
- **AND** the function SHALL NOT be called

### Requirement: Backward compatibility is maintained
The refactored CST SHALL maintain backward compatibility with existing code during the transition period.

#### Scenario: Existing serialization works
- **WHEN` serializing a `CstNode<TriviaAnn>`
- **THEN** the output SHALL match the original serialization format
- **AND** all trivia SHALL be preserved exactly

#### Scenario: Existing accessors work
- **WHEN** calling `as_atom()`, `as_list()`, or `is_tagged()`
- **THEN** the methods SHALL return the same results as before refactoring

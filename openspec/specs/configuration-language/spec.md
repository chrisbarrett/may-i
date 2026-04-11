## MODIFIED Requirements

### Requirement: AST enums are non-exhaustive
Public AST enums that are likely to gain variants SHALL be annotated with `#[non_exhaustive]` to prevent downstream exhaustive matches from breaking on additions. This applies to: Effect, Predicate, EvalError, FactPattern, Expr, CommandPattern, ArgPattern.

#### Scenario: Adding a new Effect variant
- **WHEN** a new variant is added to the Effect enum
- **THEN** downstream crates with wildcard match arms SHALL continue to compile

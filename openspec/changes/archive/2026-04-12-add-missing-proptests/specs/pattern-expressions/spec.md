## MODIFIED Requirements

### Requirement: Expression serialization roundtrips through parser
Expr values serialized to sexpr form SHALL parse back to structurally equivalent expressions.

#### Scenario: Arbitrary expression roundtrip
- **WHEN** a randomly generated Expr is converted to sexpr string and parsed via parse_expr
- **THEN** the result SHALL match the original expression

## ADDED Requirements

### Requirement: Expr::And matches only if all sub-expressions match
`Expr::And` SHALL return true only if every sub-expression matches the value. Bound facts from all sub-expressions SHALL be merged into the result.

#### Scenario: All sub-expressions match
- **WHEN** matching `Expr::And([Literal("prod"), Regex("^prod")])` against `"prod"`
- **THEN** it SHALL return matched=true

#### Scenario: One sub-expression fails
- **WHEN** matching `Expr::And([Literal("prod"), Literal("staging")])` against `"prod"`
- **THEN** it SHALL return matched=false

#### Scenario: Bound facts merge across And
- **WHEN** matching `Expr::And([Bind(:a, Wildcard), Bind(:b, Wildcard)])` against `"val"`
- **THEN** it SHALL return matched=true
- **AND** bound facts SHALL contain both `:a = "val"` and `:b = "val"`

### Requirement: Expr::Or matches if any sub-expression matches
`Expr::Or` SHALL return true if any sub-expression matches the value. Only bound facts from matching sub-expressions SHALL be included.

#### Scenario: First sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"prod"`
- **THEN** it SHALL return matched=true

#### Scenario: Later sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"staging"`
- **THEN** it SHALL return matched=true

#### Scenario: No sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"dev"`
- **THEN** it SHALL return matched=false

#### Scenario: Bound facts from matching branch only
- **WHEN** matching `Expr::Or([Bind(:a, Literal("prod")), Bind(:b, Literal("staging"))])` against `"staging"`
- **THEN** bound facts SHALL contain `:b = "staging"` but NOT `:a`

### Requirement: Expr::Not inverts match without capturing facts
`Expr::Not` SHALL return true if the inner expression does NOT match. Facts captured by the inner expression SHALL NOT be included in the result.

#### Scenario: Inner matches so Not returns false
- **WHEN** matching `Expr::Not(Literal("prod"))` against `"prod"`
- **THEN** it SHALL return matched=false

#### Scenario: Inner does not match so Not returns true
- **WHEN** matching `Expr::Not(Literal("prod"))` against `"staging"`
- **THEN** it SHALL return matched=true

#### Scenario: Not discards inner bound facts
- **WHEN** matching `Expr::Not(Bind(:a, Literal("x")))` against `"y"`
- **THEN** it SHALL return matched=true
- **AND** bound facts SHALL be empty

### Requirement: Expr::Bind captures matched value as fact
`Expr::Bind` SHALL evaluate its inner expression. If the inner expression matches, the matched value SHALL be captured as a scalar fact under the bind key.

#### Scenario: Bind captures on match
- **WHEN** matching `Expr::Bind { key: ":host", expr: Wildcard }` against `"server-01"`
- **THEN** it SHALL return matched=true
- **AND** bound facts SHALL contain `:host = "server-01"`

#### Scenario: Bind does not capture on mismatch
- **WHEN** matching `Expr::Bind { key: ":env", expr: Literal("prod") }` against `"staging"`
- **THEN** it SHALL return matched=false
- **AND** bound facts SHALL be empty

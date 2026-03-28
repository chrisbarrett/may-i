## ADDED Requirements

### Requirement: Presence query returns Match when key exists
`FactQuery::Presence` SHALL return Match when the key exists in context facts (regardless of whether the value is Scalar or Present), NoMatch when absent.

#### Scenario: Key exists as Present
- **WHEN** evaluating `(fact? :via/ssh)` against facts containing `:via/ssh` as Present
- **THEN** it SHALL return Match

#### Scenario: Key exists as Scalar
- **WHEN** evaluating `(fact? :env)` against facts containing `[:env "prod"]`
- **THEN** it SHALL return Match

#### Scenario: Key absent
- **WHEN** evaluating `(fact? :via/ssh)` against empty facts
- **THEN** it SHALL return NoMatch

### Requirement: Value query matches scalar against pattern
`FactQuery::Value` SHALL return Match when the key exists as a Scalar and its value matches the FactPattern, NoMatch otherwise.

#### Scenario: Scalar matches literal pattern
- **WHEN** evaluating `(fact? [:env "prod"])` against facts containing `[:env "prod"]`
- **THEN** it SHALL return Match

#### Scenario: Scalar does not match literal pattern
- **WHEN** evaluating `(fact? [:env "prod"])` against facts containing `[:env "staging"]`
- **THEN** it SHALL return NoMatch

#### Scenario: Key exists as Present (non-scalar) returns NoMatch
- **WHEN** evaluating `(fact? [:env "prod"])` against facts containing `:env` as Present (no scalar value)
- **THEN** it SHALL return NoMatch

#### Scenario: Key absent returns NoMatch
- **WHEN** evaluating `(fact? [:env "prod"])` against empty facts
- **THEN** it SHALL return NoMatch

### Requirement: FactPattern::Regex matches scalar values
`FactPattern::Regex` SHALL match against the scalar value using regex semantics.

#### Scenario: Regex matches
- **WHEN** matching `FactPattern::Regex("^prod")` against scalar value `"prod-server-01"`
- **THEN** it SHALL return true

#### Scenario: Regex does not match
- **WHEN** matching `FactPattern::Regex("^prod")` against scalar value `"staging-server"`
- **THEN** it SHALL return false

### Requirement: FactPattern boolean combinators
`FactPattern::And`, `FactPattern::Or`, and `FactPattern::Not` SHALL compose pattern matching with standard boolean semantics.

#### Scenario: And requires all patterns match
- **WHEN** matching `FactPattern::And([Literal("prod"), Regex("^prod")])` against `"prod"`
- **THEN** it SHALL return true

#### Scenario: And fails when one pattern mismatches
- **WHEN** matching `FactPattern::And([Literal("prod"), Literal("staging")])` against `"prod"`
- **THEN** it SHALL return false

#### Scenario: Or requires any pattern match
- **WHEN** matching `FactPattern::Or([Literal("prod"), Literal("staging")])` against `"staging"`
- **THEN** it SHALL return true

#### Scenario: Or fails when no patterns match
- **WHEN** matching `FactPattern::Or([Literal("prod"), Literal("staging")])` against `"dev"`
- **THEN** it SHALL return false

#### Scenario: Not inverts match result
- **WHEN** matching `FactPattern::Not(Literal("prod"))` against `"staging"`
- **THEN** it SHALL return true

#### Scenario: Not inverts to false
- **WHEN** matching `FactPattern::Not(Literal("prod"))` against `"prod"`
- **THEN** it SHALL return false

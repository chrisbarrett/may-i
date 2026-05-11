## ADDED Requirements

### Requirement: Expr::Or matches if any sub-expression matches

`Expr::Or` SHALL return true if any sub-expression matches the value. The evaluation SHALL short-circuit on the first matching sub-expression. Only bound facts from the first matching sub-expression SHALL be included in the result. Later alternatives SHALL NOT be evaluated once a match is found.

#### Scenario: First sub-expression matches

- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"prod"`
- **THEN** it SHALL return matched=true

#### Scenario: Later sub-expression matches

- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"staging"`
- **THEN** it SHALL return matched=true

#### Scenario: No sub-expression matches

- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"dev"`
- **THEN** it SHALL return matched=false

#### Scenario: Bound facts from first matching branch only

- **WHEN** matching `Expr::Or([Bind(:a, Literal("prod")), Bind(:b, Literal("staging"))])` against `"staging"`
- **THEN** bound facts SHALL contain `:b = "staging"` but NOT `:a`

#### Scenario: Short-circuit prevents later binding leakage

- **WHEN** matching `Expr::Or([Bind(:x, Wildcard), Bind(:y, Wildcard)])` against `"val"`
- **THEN** bound facts SHALL contain only `:x = "val"`
- **AND** `:y` SHALL NOT be present in bound facts

### Requirement: Fewer args than required patterns returns no match

When the number of available positional args is less than the number of patterns (accounting for quantifiers), positional matching SHALL return false.

#### Scenario: Zero args with one required pattern

- **WHEN** matching positional patterns `["push"]` against args `[]`
- **THEN** it SHALL return matched=false

#### Scenario: One arg with two required patterns

- **WHEN** matching positional patterns `["remote" "add"]` against args `["remote"]`
- **THEN** it SHALL return matched=false

### Requirement: Optional quantifier matches with or without arg

A `Quantifier::Optional` (?) pattern SHALL match even when the arg at that position is absent. When the arg is present, it MUST match the pattern.

#### Scenario: Optional with matching arg present

- **WHEN** matching positional pattern `"branch"?` against args `["branch"]`
- **THEN** it SHALL return matched=true

#### Scenario: Optional with non-matching arg present

- **WHEN** matching positional pattern `"branch"?` against args `["tag"]`
- **THEN** it SHALL return matched=false

#### Scenario: Optional with no arg at position

- **WHEN** matching positional patterns `["push" "origin"?]` against args `["push"]`
- **THEN** it SHALL return matched=true (optional pattern satisfied by absence)

### Requirement: OneOrMore quantifier requires at least one match

A `Quantifier::OneOrMore` (+) pattern SHALL require at least one arg at the pattern's position. All remaining args from that position onward MUST match the pattern.

#### Scenario: One matching arg

- **WHEN** matching positional pattern `*+` against args `["file1"]`
- **THEN** it SHALL return matched=true

#### Scenario: Multiple matching args

- **WHEN** matching positional pattern `*+` against args `["file1" "file2" "file3"]`
- **THEN** it SHALL return matched=true

#### Scenario: No args at position

- **WHEN** matching positional patterns `["cmd" *+]` against args `["cmd"]`
- **THEN** it SHALL return matched=false (OneOrMore requires at least one)

### Requirement: ZeroOrMore quantifier matches any count

A `Quantifier::ZeroOrMore` (*) pattern SHALL match zero or more remaining args from that position. All remaining args MUST match the pattern.

#### Scenario: Zero remaining args

- **WHEN** matching positional patterns `["cmd" **]` against args `["cmd"]`
- **THEN** it SHALL return matched=true

#### Scenario: Multiple remaining args all match

- **WHEN** matching positional pattern `**` against args `["a" "b" "c"]`
- **THEN** it SHALL return matched=true

### Requirement: Bind is valid in positional, exact, and anywhere but not forbidden

`Expr::Bind` SHALL be accepted by the parser inside `positional`, `exact`, and `anywhere` patterns. The parser SHALL reject `Expr::Bind` inside `forbidden` patterns with a clear error.

#### Scenario: Bind in positional

- **WHEN** parsing `(positional [:ssh/host *])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in exact

- **WHEN** parsing `(exact [:env "prod"])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in anywhere

- **WHEN** parsing `(anywhere [:git/branch (regex "^(main|master)$")])`
- **THEN** it SHALL succeed with a Bind expression

#### Scenario: Bind in forbidden rejected

- **WHEN** parsing `(forbidden [:key *])`
- **THEN** the parser SHALL reject it with an error explaining bind is not valid in forbidden patterns

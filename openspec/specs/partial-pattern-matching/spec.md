# partial-pattern-matching Specification

## Purpose

Quantifier semantics for positional pattern matching: `?` Optional (zero or one), `+` OneOrMore, `*` ZeroOrMore. Defines what happens when fewer args are present than the patterns demand, when an Optional pattern is satisfied by absence, and what counts as a valid OneOrMore/ZeroOrMore match.

## Requirements

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


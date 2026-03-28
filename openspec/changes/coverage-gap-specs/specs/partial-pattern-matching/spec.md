## MODIFIED Requirements

### Requirement: Forbidden patterns return Deny or Nil
`(forbidden PATTERN...)` SHALL return Deny if any pattern appears in args, Nil otherwise.

#### Scenario: Forbidden pattern found
- **WHEN** evaluating `(forbidden "--force")` against args `["push" "--force"]`
- **THEN** it SHALL return Deny

#### Scenario: Forbidden pattern not found
- **WHEN** evaluating `(forbidden "--force")` against args `["push" "origin"]`
- **THEN** it SHALL return Nil

#### Scenario: Forbidden wildcard with non-empty args
- **WHEN** evaluating `(forbidden *)` against args `["anything"]`
- **THEN** it SHALL return Deny

#### Scenario: Forbidden wildcard with empty args
- **WHEN** evaluating `(forbidden *)` against args `[]`
- **THEN** it SHALL return Allow

### Requirement: Anywhere patterns return Allow or Nil
`(anywhere PATTERN...)` SHALL return Allow if any pattern appears anywhere in args, Nil otherwise.

#### Scenario: Pattern found in args
- **WHEN** evaluating `(anywhere "--force")` against args `["push" "origin" "--force"]`
- **THEN** it SHALL return Allow

#### Scenario: Pattern not found
- **WHEN** evaluating `(anywhere "--force")` against args `["push" "origin"]`
- **THEN** it SHALL return Nil

#### Scenario: Wildcard always matches
- **WHEN** evaluating `(anywhere *)` against any args
- **THEN** it SHALL return Allow

### Requirement: Wildcard patterns always match
`*` (wildcard) in pattern position SHALL always match and return Allow.

#### Scenario: Wildcard matches anything
- **WHEN** evaluating `(positional "git" *)` against args `["git" "anything"]`
- **THEN** it SHALL return Allow

#### Scenario: Wildcard in Anywhere
- **WHEN** evaluating `(anywhere *)` against args `["x"]`
- **THEN** it SHALL return Allow

#### Scenario: Wildcard in Forbidden denies non-empty args
- **WHEN** evaluating `(forbidden *)` against args `["x"]`
- **THEN** it SHALL return Deny

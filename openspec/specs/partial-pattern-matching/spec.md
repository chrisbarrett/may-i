## ADDED Requirements

### Requirement: Positional patterns return Allow or Nil
`(positional PATTERN...)` SHALL return Allow if the args match the patterns in order, Nil otherwise.

#### Scenario: Single positional matches
- **WHEN** evaluating `(positional "push")` against args `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Single positional doesn't match
- **WHEN** evaluating `(positional "push")` against args `["status"]`
- **THEN** it SHALL return Nil

#### Scenario: Multiple positionals match
- **WHEN** evaluating `(positional "remote" "add")` against args `["remote" "add" "origin"]`
- **THEN** it SHALL return Allow

#### Scenario: Multiple positionals don't match
- **WHEN** evaluating `(positional "remote" "add")` against args `["remote" "remove"]`
- **THEN** it SHALL return Nil

### Requirement: Exact patterns return Allow or Nil
`(exact PATTERN...)` SHALL return Allow if args match exactly (no extra args), Nil otherwise.

#### Scenario: Exact match
- **WHEN** evaluating `(exact "status")` against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Exact with extra args
- **WHEN** evaluating `(exact "status")` against args `["status" "--short"]`
- **THEN** it SHALL return Nil

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

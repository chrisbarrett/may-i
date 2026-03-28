## ADDED Requirements

### Requirement: Positional effect with continuation evaluates rest
`(positional PATTERN... . EFFECT)` evaluated as an effect SHALL consume matched positional args, then evaluate EFFECT with remaining non-flag args and any bound facts merged into the context.

#### Scenario: Continuation receives remaining args
- **WHEN** evaluating `(positional "git" . (effect :allow))` against args `["git" "push"]`
- **THEN** it SHALL evaluate the continuation `(effect :allow)` with remaining args `["push"]`
- **AND** return Allow

#### Scenario: Continuation receives bound facts
- **WHEN** evaluating `(positional [:host] . (effect :allow))` against args `["prod-server" "ls"]`
- **THEN** the continuation SHALL have fact `:host = "prod-server"` in context

#### Scenario: Flags are preserved for continuation
- **WHEN** evaluating `(positional "git" . EFFECT)` against args `["git" "--verbose" "push"]`
- **THEN** remaining args passed to continuation SHALL include non-flag args after consumed prefix

### Requirement: Positional effect without continuation returns Allow on match
`(positional PATTERN...)` without dot notation SHALL return Allow when args match, Nil otherwise.

#### Scenario: Match returns Allow
- **WHEN** evaluating `(positional "push")` as effect against args `["push"]`
- **THEN** it SHALL return Allow with no reason

#### Scenario: Mismatch returns Nil
- **WHEN** evaluating `(positional "push")` as effect against args `["status"]`
- **THEN** it SHALL return Nil

### Requirement: Exact effect with continuation passes flags only
`(exact PATTERN... . EFFECT)` evaluated as an effect SHALL match exact positional arg count, then evaluate EFFECT with only the flags (args starting with `-`).

#### Scenario: Exact match evaluates continuation with flags
- **WHEN** evaluating `(exact "status" . (effect :allow))` against args `["status" "--short"]`
- **THEN** the continuation SHALL receive args `["--short"]` (flags only)
- **AND** return Allow

#### Scenario: Extra positional args return Nil
- **WHEN** evaluating `(exact "status" . (effect :allow))` against args `["status" "extra"]`
- **THEN** it SHALL return Nil (extra positional arg violates exact)

### Requirement: Exact effect without continuation returns Allow on match
`(exact PATTERN...)` without dot notation SHALL return Allow when positional arg count and patterns match exactly, Nil otherwise.

#### Scenario: Exact match returns Allow
- **WHEN** evaluating `(exact "status")` as effect against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Count mismatch returns Nil
- **WHEN** evaluating `(exact "status")` as effect against args `["status" "extra"]`
- **THEN** it SHALL return Nil

### Requirement: Anywhere effect returns Allow when literal found
`(anywhere PATTERN...)` evaluated as an effect SHALL return Allow if any pattern's literal appears in args, Nil if no pattern matches.

#### Scenario: Literal found in args
- **WHEN** evaluating `(anywhere "--force")` as effect against args `["push" "--force"]`
- **THEN** it SHALL return Allow

#### Scenario: Literal not found
- **WHEN** evaluating `(anywhere "--force")` as effect against args `["push" "origin"]`
- **THEN** it SHALL return Nil

#### Scenario: Wildcard always matches
- **WHEN** evaluating `(anywhere *)` as effect against any non-empty args
- **THEN** it SHALL return Allow

### Requirement: Forbidden effect returns Deny when found, Allow when absent
`(forbidden PATTERN...)` evaluated as an effect SHALL return Deny if any pattern's literal is found in args, Allow if none are found.

#### Scenario: Forbidden literal found
- **WHEN** evaluating `(forbidden "--force")` as effect against args `["push" "--force"]`
- **THEN** it SHALL return Deny

#### Scenario: Forbidden literal absent
- **WHEN** evaluating `(forbidden "--force")` as effect against args `["push" "origin"]`
- **THEN** it SHALL return Allow

#### Scenario: Forbidden wildcard with non-empty args
- **WHEN** evaluating `(forbidden *)` as effect against args `["anything"]`
- **THEN** it SHALL return Deny

#### Scenario: Forbidden wildcard with empty args
- **WHEN** evaluating `(forbidden *)` as effect against args `[]`
- **THEN** it SHALL return Allow

### Requirement: At effect matches by 1-based position
`(at POSITION PATTERN)` evaluated as an effect SHALL return Allow if the arg at the 1-based position matches the pattern, Nil otherwise. Out-of-bounds positions return Nil.

#### Scenario: Position in bounds and matches
- **WHEN** evaluating `(at 2 "push")` as effect against args `["git" "push"]`
- **THEN** it SHALL return Allow

#### Scenario: Position in bounds but mismatch
- **WHEN** evaluating `(at 2 "push")` as effect against args `["git" "status"]`
- **THEN** it SHALL return Nil

#### Scenario: Position out of bounds
- **WHEN** evaluating `(at 3 "push")` as effect against args `["git"]`
- **THEN** it SHALL return Nil

#### Scenario: Position zero is out of bounds
- **WHEN** evaluating `(at 0 "push")` as effect against args `["push"]`
- **THEN** it SHALL return Nil

#### Scenario: Wildcard at valid position
- **WHEN** evaluating `(at 1 *)` as effect against args `["anything"]`
- **THEN** it SHALL return Allow

### Requirement: Positional predicate matches prefix
`(positional PATTERN...)` evaluated as a predicate SHALL return Match if positional args match the pattern prefix, NoMatch otherwise. Continuation is ignored for predicate evaluation.

#### Scenario: Prefix matches
- **WHEN** evaluating `(positional "push")` as predicate against args `["push" "origin"]`
- **THEN** it SHALL return Match

#### Scenario: Prefix does not match
- **WHEN** evaluating `(positional "push")` as predicate against args `["status"]`
- **THEN** it SHALL return NoMatch

### Requirement: Exact predicate requires count and match
`(exact PATTERN...)` evaluated as a predicate SHALL return Match only when the positional arg count equals the pattern count and all patterns match.

#### Scenario: Exact match
- **WHEN** evaluating `(exact "status")` as predicate against args `["status"]`
- **THEN** it SHALL return Match

#### Scenario: Extra args
- **WHEN** evaluating `(exact "status")` as predicate against args `["status" "extra"]`
- **THEN** it SHALL return NoMatch

### Requirement: Anywhere predicate searches args
`(anywhere PATTERN)` evaluated as a predicate SHALL return Match if the literal appears anywhere in args, NoMatch otherwise. Wildcard always returns Match.

#### Scenario: Literal found
- **WHEN** evaluating `(anywhere "--force")` as predicate against args `["push" "--force"]`
- **THEN** it SHALL return Match

#### Scenario: Wildcard always matches
- **WHEN** evaluating `(anywhere *)` as predicate against any args
- **THEN** it SHALL return Match

### Requirement: Forbidden predicate returns NoMatch when found
`(forbidden PATTERN)` evaluated as a predicate SHALL return NoMatch if the forbidden literal is found, Match if absent. Wildcard with non-empty args returns NoMatch.

#### Scenario: Forbidden found
- **WHEN** evaluating `(forbidden "--force")` as predicate against args `["push" "--force"]`
- **THEN** it SHALL return NoMatch

#### Scenario: Forbidden absent
- **WHEN** evaluating `(forbidden "--force")` as predicate against args `["push"]`
- **THEN** it SHALL return Match

#### Scenario: Forbidden wildcard with args
- **WHEN** evaluating `(forbidden *)` as predicate against args `["anything"]`
- **THEN** it SHALL return NoMatch

### Requirement: At predicate matches by 1-based position
`(at POSITION PATTERN)` evaluated as a predicate SHALL return Match if the arg at 1-based position matches, NoMatch otherwise.

#### Scenario: Position matches
- **WHEN** evaluating `(at 1 "push")` as predicate against args `["push"]`
- **THEN** it SHALL return Match

#### Scenario: Position out of bounds
- **WHEN** evaluating `(at 3 "x")` as predicate against args `["a"]`
- **THEN** it SHALL return NoMatch

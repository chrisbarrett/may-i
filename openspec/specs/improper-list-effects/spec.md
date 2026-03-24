## ADDED Requirements

### Requirement: Dot notation separates match from effect
`(positional PATTERN... . EFFECT)` SHALL match the patterns, then evaluate EFFECT with the remaining unconsumed arguments.

#### Scenario: Simple dot notation with may-i
- **GIVEN** command `"ssh"` with args `["host1" "ls" "-la"]`
- **WHEN** evaluating `(positional [:host *] . (may-i *))`
- **THEN** it SHALL capture `"host1"` as `:host`, then recursively evaluate `"ls" "-la"`

#### Scenario: Dot notation with custom effect
- **WHEN** evaluating `(positional "git" . (effect :allow))` against args `["git" "push"]`
- **THEN** it SHALL match `"git"` and return Allow

### Requirement: May-i returns Nil if pattern doesn't match
`(may-i PATTERN)` SHALL return Nil if the pattern doesn't match the remaining args, otherwise return the inner command's decision.

#### Scenario: Pattern matches, evaluate inner
- **GIVEN** rule `(rule "ssh" (positional [:host *] . (may-i *)) :effect (effect :deny))`
- **AND** inner rule for `"ls"` that returns Allow
- **WHEN** evaluating `"ssh"` with args `["host1" "ls"]`
- **THEN** it SHALL return Allow (from inner evaluation)

#### Scenario: Pattern doesn't match
- **GIVEN** same rule
- **WHEN** evaluating `"ssh"` with args `["host1"]` (no command after host)
- **THEN** `(may-i *)` SHALL return Nil
- **AND** the rule SHALL fall through to default `(effect :deny)`

### Requirement: Multiple patterns before dot
`(positional A B C . EFFECT)` SHALL match A, B, and C in sequence, then evaluate EFFECT with remaining args.

#### Scenario: Multiple patterns
- **WHEN** evaluating `(positional "git" "remote" "add" . (effect :allow))` against args `["git" "remote" "add" "origin" "url"]`
- **THEN** it SHALL match all three patterns and return Allow

### Requirement: Exact patterns support dot notation
`(exact PATTERN... . EFFECT)` SHALL require exact match of patterns (no extra args before dot), then evaluate EFFECT.

#### Scenario: Exact with dot
- **WHEN** evaluating `(exact "git" "status" . (effect :allow))` against args `["git" "status"]`
- **THEN** it SHALL return Allow

#### Scenario: Exact with extra args before dot
- **WHEN** evaluating `(exact "git" "status" . (effect :allow))` against args `["git" "status" "--short"]`
- **THEN** it SHALL return Nil (extra arg violates exact)

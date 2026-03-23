## ADDED Requirements

### Requirement: And combinator short-circuits on Nil
`(and EFFECT...)` SHALL evaluate effects left-to-right, returning the first Nil encountered, or the last effect's result if all are non-Nil.

#### Scenario: All effects succeed
- **WHEN** evaluating `(and (effect :allow) (effect :ask))`
- **THEN** it SHALL return Ask (the last effect)

#### Scenario: First effect returns Nil
- **WHEN** evaluating `(and (positional "push") (effect :allow))` against args `["status"]`
- **THEN** it SHALL return Nil (short-circuit on positional)

#### Scenario: Middle effect returns Nil
- **WHEN** evaluating `(and (effect :allow) (positional "push") (effect :ask))` against args `["status"]`
- **THEN** it SHALL return Nil (from positional)

### Requirement: Or combinator returns first non-Nil
`(or EFFECT...)` SHALL evaluate effects left-to-right, returning the first non-Nil result, or Nil if all return Nil.

#### Scenario: First effect succeeds
- **WHEN** evaluating `(or (effect :allow) (effect :ask))`
- **THEN** it SHALL return Allow

#### Scenario: First returns Nil, second succeeds
- **WHEN** evaluating `(or (positional "push") (effect :allow))` against args `["status"]`
- **THEN** it SHALL return Allow (falls through to second)

#### Scenario: All return Nil
- **WHEN** evaluating `(or (positional "push") (positional "status"))` against args `["remote"]`
- **THEN** it SHALL return Nil

### Requirement: Not combinator inverts decisions
`(not EFFECT)` SHALL return Allow if EFFECT returns Nil, Nil if EFFECT returns Allow, and pass through Ask/Deny unchanged.

#### Scenario: Not of Nil returns Allow
- **WHEN** evaluating `(not (positional "push"))` against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Not of Allow returns Nil
- **WHEN** evaluating `(not (positional "push"))` against args `["push"]`
- **THEN** it SHALL return Nil

### Requirement: When evaluates effect if predicate matches
`(when PREDICATE EFFECT)` SHALL evaluate EFFECT if PREDICATE matches, otherwise return Nil.

#### Scenario: Predicate matches
- **WHEN** evaluating `(when (fact? :via/ssh) (effect :allow))` with fact `:via/ssh` present
- **THEN** it SHALL return Allow

#### Scenario: Predicate doesn't match
- **WHEN** evaluating `(when (fact? :via/ssh) (effect :allow))` without fact
- **THEN** it SHALL return Nil

### Requirement: Unless evaluates effect if predicate doesn't match
`(unless PREDICATE EFFECT)` SHALL evaluate EFFECT if PREDICATE doesn't match, otherwise return Nil.

#### Scenario: Predicate doesn't match
- **WHEN** evaluating `(unless (positional "rm") (effect :allow))` against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: Predicate matches
- **WHEN** evaluating `(unless (positional "rm") (effect :allow))` against args `["rm"]`
- **THEN** it SHALL return Nil

### Requirement: If chooses branch based on predicate
`(if PREDICATE THEN ELSE)` SHALL evaluate THEN if PREDICATE matches, otherwise evaluate ELSE.

#### Scenario: Predicate matches
- **WHEN** evaluating `(if (positional "push") (effect :allow) (effect :ask))` against args `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Predicate doesn't match
- **WHEN** evaluating `(if (positional "push") (effect :allow) (effect :ask))` against args `["status"]`
- **THEN** it SHALL return Ask

### Requirement: Cond evaluates first matching branch
`(cond ((P E)...) [else E])` SHALL evaluate the effect of the first matching predicate, or the else effect if none match.

#### Scenario: First branch matches
- **WHEN** evaluating `(cond ((positional "push") (effect :allow)) ((positional "rm") (effect :deny)) (else (effect :ask)))` against args `["push"]`
- **THEN** it SHALL return Allow

#### Scenario: Second branch matches
- **WHEN** evaluating same cond against args `["rm"]`
- **THEN** it SHALL return Deny

#### Scenario: No branch matches, use else
- **WHEN** evaluating same cond against args `["status"]`
- **THEN** it SHALL return Ask

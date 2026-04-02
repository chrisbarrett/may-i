## MODIFIED Requirements

### Requirement: Cond evaluates first matching branch
`(cond ((PREDICATE EFFECT)...) [(else EFFECT)])` SHALL evaluate the effect of the first branch whose predicate matches. Predicates for branches after the first match SHALL NOT be evaluated. If no branch matches and an `else` clause is present, it evaluates the else effect. If no branch matches and there is no else, it returns Nil. (CHANGED: added explicit requirement that later branch predicates are not evaluated after a match)

#### Scenario: First branch matches
- **WHEN** evaluating `(cond ((positional "push") (effect :ask)) ((positional "rm") (effect :deny)) (else (effect :allow)))` against args `["push"]`
- **THEN** it SHALL return Ask

#### Scenario: No branch matches, else used
- **WHEN** evaluating the same form against args `["status"]`
- **THEN** it SHALL return Allow

#### Scenario: No branch matches, no else
- **GIVEN** a cond with no else clause
- **WHEN** no branch predicate matches
- **THEN** it SHALL return Nil

#### Scenario: Later branch predicates are not evaluated after match
- **GIVEN** `(cond ((positional "push") (effect :ask)) ((positional "pull") (effect :deny)))`
- **WHEN** evaluating against args `["push"]`
- **THEN** the predicate `(positional "pull")` SHALL NOT be evaluated
- **AND** it SHALL appear as `Skipped` in the trace fold output

### Requirement: Predicate to_doc serialization uses canonical keywords
When a `Predicate::Fact` is serialized via `to_doc()`, the output SHALL use the keyword `fact?` to match the canonical DSL syntax. (CHANGED: was emitting `has`, now emits `fact?`)

#### Scenario: Fact predicate serializes as fact?
- **WHEN** calling `to_doc()` on `Predicate::Fact(FactQuery::Presence { key: ":via/ssh" })`
- **THEN** the resulting Doc SHALL contain the atom `fact?`
- **AND** SHALL NOT contain the atom `has`

#### Scenario: Roundtrip through to_doc preserves parseable syntax
- **WHEN** a `Predicate::Fact` is serialized via `to_doc()` and the output is
  rendered to a string
- **THEN** the string SHALL be parseable by the config parser as a valid
  predicate

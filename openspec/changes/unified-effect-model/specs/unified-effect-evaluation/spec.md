## ADDED Requirements

### Requirement: Effects return decisions or Nil
All effect forms SHALL return either a terminal decision (Allow, Ask, Deny) or Nil to signal "no match, continue evaluating".

#### Scenario: Terminal effect returns decision
- **WHEN** evaluating `(effect :allow)`
- **THEN** it SHALL return Allow

#### Scenario: Pattern returns Nil on mismatch
- **WHEN** evaluating `(positional "push")` against args `["status"]`
- **THEN** it SHALL return Nil

#### Scenario: Pattern returns Allow on match
- **WHEN** evaluating `(positional "push")` against args `["push"]`
- **THEN** it SHALL return Allow

### Requirement: Rule evaluation chains effects
Rules SHALL evaluate effects in sequence until a non-Nil result is found, then use the `:effect` default if all return Nil.

#### Scenario: First effect matches
- **GIVEN** rule `(rule "git" (positional "push") :effect (effect :ask))`
- **WHEN** evaluating command `"git"` with args `["push"]`
- **THEN** it SHALL return Allow (from positional match)

#### Scenario: No effects match, use default
- **GIVEN** rule `(rule "git" (positional "push") :effect (effect :ask))`
- **WHEN** evaluating command `"git"` with args `["status"]`
- **THEN** it SHALL return Ask (the default)

### Requirement: Shorthand `:effect` syntax
`:effect` SHALL accept keyword shorthand (`:allow`, `:ask`, `:deny`) and vector shorthand (`[:keyword "reason"]`).

#### Scenario: Keyword shorthand
- **GIVEN** rule `(rule "git" :effect :allow)`
- **WHEN** evaluating command `"git"`
- **THEN** it SHALL return Allow

#### Scenario: Vector shorthand with reason
- **GIVEN** rule `(rule "git" :effect [:ask "confirm deletion"])`
- **WHEN** evaluating command `"git"`
- **THEN** it SHALL return Ask with reason "confirm deletion"

### Requirement: Command pattern is an effect
The first argument to `rule` SHALL be treated as an effect that must return non-Nil for the rule to apply.

#### Scenario: Command literal matches
- **GIVEN** rule `(rule "git" :effect (effect :allow))`
- **WHEN** evaluating command `"git"`
- **THEN** it SHALL return Allow

#### Scenario: Command literal doesn't match
- **GIVEN** rule `(rule "git" :effect (effect :allow))`
- **WHEN** evaluating command `"cargo"`
- **THEN** the rule SHALL not apply

#### Scenario: Command or pattern
- **GIVEN** rule `(rule (or "git" "gh") :effect (effect :allow))`
- **WHEN** evaluating command `"gh"`
- **THEN** it SHALL return Allow

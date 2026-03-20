## ADDED Requirements

### Requirement: (define NAME PREDICATE) creates named predicates
The DSL SHALL support defining reusable named predicates using `(define NAME PREDICATE)`.

#### Scenario: Simple named predicate
- **WHEN** config contains `(define safe-git (positional (or "status" "log")))`
- **THEN** the name `safe-git` SHALL be usable in rules

#### Scenario: Named predicate in rule
- **WHEN** a rule references a defined predicate `(rule "git" safe-git (effect :allow))`
- **THEN** the predicate SHALL be resolved and evaluated correctly

#### Scenario: Named predicate with boolean logic
- **WHEN** a named predicate contains boolean combinators
- **THEN** it SHALL be usable anywhere a predicate is expected

### Requirement: Named predicates can reference other named predicates
The system SHALL support named predicates that reference other named predicates.

#### Scenario: Chained definitions
- **WHEN** config contains `(define a (has :x))` and `(define b (and a (has :y)))`
- **THEN** `b` SHALL resolve to `(and (has :x) (has :y))`

### Requirement: Duplicate definitions are rejected
The system SHALL reject configs with duplicate define names.

#### Scenario: Duplicate name
- **WHEN** config contains two `(define foo ...)` with the same name
- **THEN** parsing SHALL fail with a clear error message

### Requirement: Undefined names are rejected
The system SHALL reject predicates that reference undefined names.

#### Scenario: Undefined reference
- **WHEN** a rule references `undefined-predicate`
- **THEN** parsing SHALL fail with a clear error message

### Requirement: Cyclic definitions are rejected
The system SHALL reject configs with cyclic define references.

#### Scenario: Direct cycle
- **WHEN** config contains `(define a b)` and `(define b a)`
- **THEN** parsing SHALL fail with a clear error message about the cycle

#### Scenario: Indirect cycle
- **WHEN** config contains `(define a b)`, `(define b c)`, and `(define c a)`
- **THEN** parsing SHALL fail with a clear error message about the cycle

## ADDED Requirements

### Requirement: Facts are queried with (has ...)
The DSL SHALL support querying facts using the `(has ...)` form.

#### Scenario: Presence query
- **WHEN** a rule contains `(has :via/ssh)`
- **THEN** the predicate matches when the `:via/ssh` fact is present

#### Scenario: Exact value query
- **WHEN** a rule contains `(has [:opencode/agent "build"])`
- **THEN** the predicate matches when `:opencode/agent` has value "build"

#### Scenario: Wildcard value query
- **WHEN** a rule contains `(has [:ssh/host *])`
- **THEN** the predicate matches when `:ssh/host` has any scalar value

#### Scenario: Regex value query
- **WHEN** a rule contains `(has [:ssh/host (regex "^prod-")])`
- **THEN** the predicate matches when `:ssh/host` value matches the regex

### Requirement: Arguments are queried with arg-specific forms
The DSL SHALL support querying arguments using `(positional ...)`, `(exact ...)`, `(anywhere ...)`, and `(forbidden ...)` forms.

#### Scenario: Positional matching
- **WHEN** a rule contains `(positional "push")`
- **THEN** the predicate matches when the first positional argument is "push"

#### Scenario: Anywhere matching
- **WHEN** a rule contains `(anywhere "--force")`
- **THEN** the predicate matches when "--force" appears anywhere in arguments

#### Scenario: Forbidden matching
- **WHEN** a rule contains `(forbidden "--dangerous")`
- **THEN** the predicate matches when "--dangerous" does NOT appear in arguments

### Requirement: Predicates can be combined with boolean operators
The DSL SHALL support combining predicates with `and`, `or`, and `not`.

#### Scenario: AND combination
- **WHEN** a rule contains `(and (has :via/ssh) (positional "push"))`
- **THEN** the predicate matches only when BOTH conditions are true

#### Scenario: OR combination
- **WHEN** a rule contains `(or (positional "status") (positional "log"))`
- **THEN** the predicate matches when EITHER condition is true

#### Scenario: NOT combination
- **WHEN** a rule contains `(not (anywhere "--force"))`
- **THEN** the predicate matches when the argument is NOT present

#### Scenario: Nested combinations
- **WHEN** a rule contains `(and (has :via/ssh) (or (positional "push") (positional "pull")))`
- **THEN** the predicate evaluates the nested boolean logic correctly

### Requirement: Fact and argument queries can be freely mixed
The DSL SHALL allow mixing `(has ...)` with argument queries in boolean combinations.

#### Scenario: Mixed fact and argument in AND
- **WHEN** a rule contains `(and (has :client/opencode) (positional "build"))`
- **THEN** the predicate matches when the fact is present AND the argument matches

#### Scenario: Mixed fact and argument in OR
- **WHEN** a rule contains `(or (has :via/ssh) (positional "--local"))`
- **THEN** the predicate matches when either the fact is present OR the argument matches

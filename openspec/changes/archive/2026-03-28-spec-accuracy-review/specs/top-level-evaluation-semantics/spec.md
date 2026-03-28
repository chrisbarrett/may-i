## ADDED Requirements

### Requirement: Evaluator dispatches rules as an implicit or
The evaluator SHALL try rules in declaration order, returning the first non-Nil result. This is semantically equivalent to wrapping all user-defined rules in an `(or ...)` form.

#### Scenario: First matching rule wins
- **GIVEN** rules for `"git"` (Allow) and `"git"` (Deny) in that order
- **WHEN** evaluating command `"git"`
- **THEN** the evaluator SHALL return Allow from the first rule

#### Scenario: Non-matching rules are skipped
- **GIVEN** rules for `"git"` and `"cargo"`
- **WHEN** evaluating command `"cargo"`
- **THEN** the `"git"` rule SHALL return Nil and be skipped
- **AND** the `"cargo"` rule SHALL be evaluated

### Requirement: Global fallback is Ask
When no rule produces a non-Nil result, the evaluator SHALL return Ask. This is the implicit default at the end of the rule list.

#### Scenario: Unmatched command returns Ask
- **GIVEN** rules only for `"git"` and `"cargo"`
- **WHEN** evaluating command `"curl"`
- **THEN** the evaluator SHALL return Ask

#### Scenario: All rules return Nil
- **GIVEN** a rule `(rule "git" (positional "push") :effect (effect :allow))`
- **WHEN** evaluating command `"cargo" ["build"]`
- **THEN** the evaluator SHALL return Ask

### Requirement: Nil never surfaces to callers
The evaluator's public API SHALL always return one of Allow, Ask, or Deny. Nil is an internal evaluation mechanism only.

#### Scenario: Nil is resolved before returning
- **WHEN** evaluation completes for any command against any configuration
- **THEN** the result SHALL be Allow, Ask, or Deny
- **AND** Nil SHALL NOT appear in the result

### Requirement: Recursion depth exceeded returns Ask
When recursive evaluation via `(may-i *)` exceeds the recursion depth limit, the evaluator SHALL return Ask with a reason describing the limit.

#### Scenario: Deep nesting hits limit
- **GIVEN** a recursion limit of 10
- **WHEN** nested `(may-i *)` evaluation exceeds depth 10
- **THEN** the evaluator SHALL return Ask with reason mentioning the limit

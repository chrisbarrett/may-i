## ADDED Requirements

### Requirement: Effects can be combined with Case
The DSL SHALL support `(case ...)` for branching effects based on predicates.

#### Scenario: Case with multiple branches
- **WHEN** a rule contains `(case ((positional "push") (effect :ask)) ((positional "status") (effect :allow)))`
- **THEN** the first matching branch's effect SHALL be applied

#### Scenario: Case with else branch
- **WHEN** a rule contains `(case (...) (...) (else (effect :deny)))`
- **THEN** the else branch SHALL be applied when no other branch matches

#### Scenario: Case with implicit else
- **WHEN** a case has no else branch and no predicate matches
- **THEN** the rule SHALL fail to match (allowing other rules to be tried)

### Requirement: Sugar forms are preserved in AST
The DSL SHALL preserve `when`, `unless`, and `if` as dedicated AST nodes for trace reconstruction.

#### Scenario: When form
- **WHEN** a rule contains `(when (has :via/ssh) (effect :ask))`
- **THEN** the trace SHALL show the `when` form, not desugared `case`

#### Scenario: Unless form
- **WHEN** a rule contains `(unless (positional "--force") (effect :allow))`
- **THEN** the trace SHALL show the `unless` form, not desugared `case`

#### Scenario: If form with else
- **WHEN** a rule contains `(if (has :via/ssh) (effect :ask) (effect :allow))`
- **THEN** the trace SHALL show the `if` form with both branches

#### Scenario: If form without else
- **WHEN** a rule contains `(if (has :via/ssh) (effect :ask))`
- **THEN** the trace SHALL show the `if` form with no else branch

### Requirement: Effects can include reasons
All effect types SHALL support optional string reasons.

#### Scenario: Allow with reason
- **WHEN** a rule contains `(effect :allow "Safe read-only operation")`
- **THEN** the reason SHALL be included in the decision output

#### Scenario: Ask with reason
- **WHEN** a rule contains `(effect :ask "Network operation requires approval")`
- **THEN** the reason SHALL be included in the decision output

#### Scenario: Deny with reason
- **WHEN** a rule contains `(effect :deny "Dangerous operation")`
- **THEN** the reason SHALL be included in the decision output

## REMOVED Requirements

### Requirement: Bare keyword effect shorthand
**Reason**: Redundant syntax — `(effect :allow)` is the canonical form. Bare keywords (`:allow`, `:ask`, `:deny`) added parser complexity without expressiveness.
**Migration**: Use `(effect :allow)`, `(effect :ask "reason")`, or `(effect :deny)` instead.

### Requirement: Vector effect shorthand
**Reason**: Redundant syntax — `(effect :ask "reason")` is the canonical form. Vector shorthand (`[:ask "reason"]`) is not needed.
**Migration**: Use `(effect :ask "reason")` instead of `[:ask "reason"]`.

### Requirement: :effect keyword marker in rules
**Reason**: The `:effect` keyword marker in rules (e.g., `(rule "git" :effect :allow)`) was an artefact of the v1 migration pipeline. It is redundant since `(effect ...)` forms are self-identifying.
**Migration**: Use `(rule "git" (effect :allow))` instead of `(rule "git" :effect :allow)`.

## MODIFIED Requirements

### Requirement: Effect parsing accepts only canonical forms
The effect parser SHALL accept only the canonical `(effect KEYWORD)` and `(effect KEYWORD REASON)` forms for terminal effects. Bare keyword atoms (`:allow`, `:ask`, `:deny`) and vector shorthand (`[:keyword "reason"]`) SHALL NOT be accepted as standalone effect forms. Command literals and pattern forms (`positional`, `exact`, `anywhere`, `forbidden`, `and`, `or`, `not`, `when`, `unless`, `if`, `cond`, `may-i`) SHALL continue to be accepted.

#### Scenario: Canonical effect form accepted
- **WHEN** parsing `(effect :allow)`
- **THEN** it SHALL produce an Allow effect with no reason

#### Scenario: Canonical effect with reason accepted
- **WHEN** parsing `(effect :ask "confirm push")`
- **THEN** it SHALL produce an Ask effect with reason "confirm push"

#### Scenario: Bare keyword rejected
- **WHEN** parsing `:allow` as a standalone effect (not inside an `(effect ...)` form)
- **THEN** parsing SHALL fail with an error

#### Scenario: Vector shorthand rejected
- **WHEN** parsing `[:ask "reason"]` as an effect
- **THEN** parsing SHALL fail with an error

### Requirement: Rule parsing does not skip :effect keyword
The rule parser SHALL NOT silently skip `:effect` atoms. All items after the command effect in a rule SHALL be parsed as effects or checks. An unrecognised atom SHALL produce a parse error.

#### Scenario: Rule with canonical effect
- **WHEN** parsing `(rule "git" (effect :allow))`
- **THEN** it SHALL produce a rule with command "git" and Allow effect

#### Scenario: Rule with :effect keyword rejected
- **WHEN** parsing `(rule "git" :effect (effect :allow))`
- **THEN** parsing SHALL fail because `:effect` is not a valid effect form

### Requirement: V1 migration emits canonical effect forms
The v1 migration pipeline SHALL emit `(effect ...)` forms in rule output. It SHALL NOT emit `:effect` keyword markers or bare keyword effects. Rules without an explicit effect SHALL receive `(effect :ask)` as the default.

#### Scenario: Simple rule migration
- **WHEN** migrating `(rule (command "git") (effect :allow))`
- **THEN** the output SHALL contain `(effect :allow)` (not `:effect :allow`)

#### Scenario: Rule with context migration
- **WHEN** migrating `(rule (command "git") (context is-safe) (effect :allow))`
- **THEN** the output SHALL contain `(when is-safe (effect :allow))`

#### Scenario: Rule with effect and reason migration
- **WHEN** migrating `(rule (command "rm") (effect :deny "dangerous"))`
- **THEN** the output SHALL contain `(effect :deny "dangerous")` (not `:effect [:deny "dangerous"]`)

#### Scenario: Default effect added to rules without one
- **WHEN** migrating a v1 rule that has no effect form and no conditional effects
- **THEN** the output SHALL contain `(effect :ask)` as the default

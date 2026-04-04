## MODIFIED Requirements

### Requirement: Rule parsing does not skip :effect keyword
The rule parser SHALL accept exactly two positional arguments: a command form and a single effect form. Optional `(check ...)` forms MAY follow. Rules with zero body effects or more than one non-check body form SHALL produce a parse error. (CHANGED: was allowing arbitrary EFFECT..., now requires exactly one)

#### Scenario: Rule with canonical effect
- **WHEN** parsing `(rule "git" (effect :allow))`
- **THEN** it SHALL produce a rule with command "git" and Allow effect

#### Scenario: Rule with :effect keyword rejected
- **WHEN** parsing `(rule "git" :effect (effect :allow))`
- **THEN** parsing SHALL fail because `:effect` is not a valid effect form

#### Scenario: Rule with no body effect rejected
- **WHEN** parsing `(rule "git")`
- **THEN** parsing SHALL fail with an error indicating the rule requires an effect

#### Scenario: Rule with multiple body effects rejected
- **WHEN** parsing `(rule "git" (positional "push") (effect :ask))`
- **THEN** parsing SHALL fail with an error indicating the rule accepts exactly one effect
- **AND** the error SHALL suggest using combinators like `(and ...)` or `(or ...)`

#### Scenario: Rule with combinator as single effect
- **WHEN** parsing `(rule "git" (and (positional "push") (effect :ask)))`
- **THEN** it SHALL produce a valid rule with a single And effect

#### Scenario: Rule with cond as single effect
- **WHEN** parsing `(rule "git" (cond ((positional "push") (effect :ask)) (else (effect :allow))))`
- **THEN** it SHALL produce a valid rule with a single Cond effect

#### Scenario: Rule with check alongside effect
- **WHEN** parsing `(rule "git" (effect :allow) (check :allow "git status"))`
- **THEN** it SHALL produce a valid rule with one effect and one check

### Requirement: V1 migration emits canonical effect forms
The v1 migration pipeline SHALL emit rules with exactly one effect form. Rules that would produce multiple effects after migration SHALL have those effects wrapped in a combinator (`and` or `or` as appropriate). Rules without an explicit effect SHALL receive `(effect :ask)` as the sole effect. (CHANGED: migration must produce single-effect rules)

#### Scenario: Simple rule migration
- **WHEN** migrating `(rule (command "git") (effect :allow))`
- **THEN** the output SHALL be `(rule "git" (effect :allow))` with a single effect

#### Scenario: Rule with context migration
- **WHEN** migrating `(rule (command "git") (context is-safe) (effect :allow))`
- **THEN** the output SHALL contain `(when is-safe (effect :allow))` as the single effect

#### Scenario: Rule with effect and reason migration
- **WHEN** migrating `(rule (command "rm") (effect :deny "dangerous"))`
- **THEN** the output SHALL contain `(effect :deny "dangerous")` as the single effect

#### Scenario: Default effect added to rules without one
- **WHEN** migrating a v1 rule that has no effect form and no conditional effects
- **THEN** the output SHALL contain `(effect :ask)` as the single effect

#### Scenario: Rule with args and effect migration
- **WHEN** migrating `(rule (command "git") (args (positional "push")) (effect :ask))`
- **THEN** the output SHALL wrap both in a combinator: `(rule "git" (and (positional "push") (effect :ask)))`

**Note:** Any syntax changes in this spec MUST be reflected in `REFERENCE.txt` at the repository root.

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

## ADDED Requirements

### Requirement: Named references collected from If effects
The define resolver SHALL collect named predicate references from all parts of an `Effect::If`: the predicate, the then-effect, and the else-effect.

#### Scenario: Named predicate in If predicate
- **GIVEN** a define `(define :is-ssh (fact? :via/ssh))`
- **AND** an If effect `(if :is-ssh (effect :deny) (effect :allow))`
- **WHEN** collecting named references
- **THEN** `:is-ssh` SHALL be found in the collected references

#### Scenario: Named predicate nested in If branches
- **GIVEN** a define `(define :is-ssh (fact? :via/ssh))`
- **AND** an If effect `(if (positional "cmd") (when :is-ssh (effect :deny)) (effect :allow))`
- **WHEN** collecting named references
- **THEN** `:is-ssh` SHALL be found via recursion into the then-branch

### Requirement: Named references collected from Cond effects
The define resolver SHALL collect named predicate references from all Cond branches and the optional fallback.

#### Scenario: Named predicate in Cond branch
- **GIVEN** a define `(define :is-prod (fact? [:env "prod"]))`
- **AND** a Cond effect with branch `(:is-prod (effect :deny))`
- **WHEN** collecting named references
- **THEN** `:is-prod` SHALL be found

#### Scenario: Named predicate in Cond fallback
- **GIVEN** a define `(define :safe (fact? :safe))`
- **AND** a Cond effect with fallback `(when :safe (effect :allow))`
- **WHEN** collecting named references
- **THEN** `:safe` SHALL be found via recursion into the fallback

### Requirement: Named references collected from And/Or/Not effects
The define resolver SHALL recurse into `Effect::And`, `Effect::Or`, and `Effect::Not` to collect named predicate references.

#### Scenario: Named predicate inside And effect
- **GIVEN** a define `(define :check (fact? :ok))`
- **AND** an And effect `(and (when :check (effect :allow)) (effect :ask))`
- **WHEN** collecting named references
- **THEN** `:check` SHALL be found

#### Scenario: Named predicate inside Not effect
- **GIVEN** a define `(define :check (fact? :ok))`
- **AND** a Not effect `(not (when :check (effect :allow)))`
- **WHEN** collecting named references
- **THEN** `:check` SHALL be found

### Requirement: Resolution inlines named predicates through nested effects
`resolve_effect_predicates` SHALL recursively replace named predicates with their definitions through If, Cond, And, Or, and Not effect structures.

#### Scenario: Resolve If effect
- **GIVEN** define `(define :is-ssh (fact? :via/ssh))`
- **AND** effect `(if :is-ssh (effect :deny) (effect :allow))`
- **WHEN** resolving predicates
- **THEN** `:is-ssh` SHALL be replaced with `(fact? :via/ssh)` in the resolved If

#### Scenario: Resolve Cond effect with multiple branches
- **GIVEN** defines `(define :is-ssh (fact? :via/ssh))` and `(define :is-prod (fact? [:env "prod"]))`
- **AND** effect `(cond (:is-ssh (effect :ask)) (:is-prod (effect :deny)) (else (effect :allow)))`
- **WHEN** resolving predicates
- **THEN** both `:is-ssh` and `:is-prod` SHALL be replaced with their definitions

#### Scenario: Resolve And/Or predicate combinators
- **GIVEN** define `(define :check (fact? :ok))`
- **AND** predicate `(and :check (positional "safe"))`
- **WHEN** resolving predicates
- **THEN** `:check` SHALL be replaced with `(fact? :ok)` inside the And

#### Scenario: Resolve Not predicate
- **GIVEN** define `(define :check (fact? :ok))`
- **AND** predicate `(not :check)`
- **WHEN** resolving predicates
- **THEN** `:check` SHALL be replaced with `(fact? :ok)` inside the Not

#### Scenario: Undefined reference produces error
- **GIVEN** no defines
- **AND** effect with named predicate `:nonexistent`
- **WHEN** resolving predicates
- **THEN** it SHALL return a ResolutionError

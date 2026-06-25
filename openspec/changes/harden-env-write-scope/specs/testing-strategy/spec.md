## ADDED Requirements

### Requirement: Check cases simulate the entry environment with `(with-env …)`

A `(check …)` case SHALL be able to declare a simulated entry environment by
wrapping entries in `(with-env [NAME …] …)`. The form SHALL list
environment-variable names — no values, matching the names-only entry
environment defined in `facts` — and SHALL contain one or more decision-tagged
check entries. `(with-env …)` forms SHALL nest, and inner names SHALL merge with
outer names by set union, mirroring `(with-facts …)`. `(with-env …)` and
`(with-facts …)` SHALL compose in either nesting order.

#### Scenario: Declared name floors a bare reassignment

- **GIVEN** the check case `(with-env ["PATH"] (ask "PATH=/evil:$PATH"))`
- **WHEN** `may-i check` runs it
- **THEN** the case SHALL pass: `PATH` ∈ the simulated entry environment makes
  the bare reassignment reach a child and floor to `:ask`

#### Scenario: Undeclared name leaves a bare assignment shell-local

- **GIVEN** the check case `(allow "MY_TMP=/x ls")` with no `(with-env …)`
- **WHEN** `may-i check` runs it
- **THEN** the case SHALL pass: `MY_TMP` ∉ the empty entry environment, so the
  assignment is shell-local and does not floor

#### Scenario: Nested with-env merges by union

- **GIVEN** `(with-env ["PATH"] (with-env ["LD_PRELOAD"] (ask "LD_PRELOAD=/x echo hi")))`
- **WHEN** `may-i check` runs it
- **THEN** the inner case SHALL evaluate with both `PATH` and `LD_PRELOAD`
  present in the entry environment

### Requirement: An untested scope-dependent env rule is advised

`may-i check` SHALL emit a `warn`-level advisory when a config defines an env
decision whose result depends on the entry environment — a `(scope …)`
predicate, or reliance on the reaching-write floor for a name dangerous only
when already exported — but no `(check …)` case declares that name in a
`(with-env …)`. The advisory SHALL explain that the hermetic default entry
environment is empty and so does not exercise the always-exported names
(`PATH`, `LD_*`, …) the rule guards. The advisory SHALL NOT fail the check run on
its own.

#### Scenario: Scope rule without with-env coverage warns

- **GIVEN** a config with `(env "PATH" (when (scope reaches-child) (ask)))` and
  no check case wrapping a `PATH` assignment in `(with-env ["PATH"] …)`
- **WHEN** `may-i check` runs
- **THEN** an advisory at `warn` level SHALL report the untested
  scope-dependent rule
- **AND** the check run SHALL NOT fail solely because of the advisory

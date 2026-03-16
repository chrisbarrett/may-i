## ADDED Requirements

### Requirement: Top-level check forms parse successfully
The system SHALL accept `(check ...)` forms at the top level of configuration files.

#### Scenario: Simple top-level check
- **WHEN** the config file contains `(check :allow "ls")`
- **THEN** parsing succeeds with one top-level check

#### Scenario: Top-level check with context
- **WHEN** the config file contains `(check (with-facts [[:client/opencode]] :allow "git status"))`
- **THEN** parsing succeeds with the context facts applied to the check

#### Scenario: Multiple top-level checks
- **WHEN** the config file contains multiple `(check ...)` forms
- **THEN** all checks are collected in order

### Requirement: Top-level checks evaluate against complete rule set
The system SHALL evaluate top-level checks using the full rule engine with all configured rules and wrappers.

#### Scenario: Check matches a rule
- **GIVEN** a config with a rule allowing `ls` and a top-level check `:allow "ls"`
- **WHEN** checks are executed
- **THEN** the check passes

#### Scenario: Check uses context facts
- **GIVEN** a config with a rule requiring context and a top-level check with `with-facts` providing that context
- **WHEN** checks are executed
- **THEN** the check evaluates using the provided context

#### Scenario: Check fails when expectation mismatches
- **GIVEN** a config with a rule that denies `rm` and a top-level check `:allow "rm"`
- **WHEN** checks are executed
- **THEN** the check fails with expected `:allow` but actual `:deny`

### Requirement: Top-level and embedded checks coexist
The system SHALL support both top-level checks and embedded rule checks in the same configuration file.

#### Scenario: Mixed checks
- **GIVEN** a config with embedded checks in rules AND top-level checks
- **WHEN** checks are executed
- **THEN** all checks run and results include both types

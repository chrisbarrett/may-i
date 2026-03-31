## MODIFIED Requirements

### Requirement: Top-level checks evaluate against complete rule set
The system SHALL evaluate top-level checks using the full rule engine with all configured rules and wrappers. Check evaluation SHALL use `PureFold` by default; the CLI check command SHALL use `TracingFold` to capture traces for failure reporting. (CHANGED: check evaluation now uses the `EvalFold` trait; `CheckResult` no longer carries a trace field)

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

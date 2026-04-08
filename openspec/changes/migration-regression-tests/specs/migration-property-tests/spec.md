## MODIFIED Requirements

### Requirement: Property test generators for compound v1 forms
The migration property test suite SHALL include generators for compound v1 configurations that exercise multiple rewrite rules simultaneously.

#### Scenario: Compound rule generator
- **WHEN** the any_v1_compound_rule generator produces a v1 config
- **THEN** it SHALL include (command ...), (context ...), and (args ...) in a single rule

#### Scenario: Wrapper generator
- **WHEN** the any_v1_wrapper generator produces a wrapper form
- **THEN** it SHALL include random positional patterns, flag patterns, and capture markers

#### Scenario: Full config generator
- **WHEN** the any_v1_config generator produces a config
- **THEN** it SHALL mix rules, wrappers, defcontexts, and defines

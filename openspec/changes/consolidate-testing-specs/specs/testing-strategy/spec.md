## ADDED Requirements

### Requirement: All CLI subcommands have integration tests

Every user-facing CLI subcommand SHALL have at least one happy-path and one error-path integration test that invokes the may-i binary as a subprocess.

#### Scenario: check subcommand happy path

- **WHEN** `may-i check` is run with a valid config
- **THEN** the exit code SHALL be 0 and output SHALL list check results

#### Scenario: check subcommand with failures

- **WHEN** `may-i check` is run with a config containing failing checks
- **THEN** the exit code SHALL be non-zero

#### Scenario: parse subcommand

- **WHEN** `may-i parse` is run with a valid shell command
- **THEN** the exit code SHALL be 0 and output SHALL show parsed structure

#### Scenario: migrate subcommand as subprocess

- **WHEN** `may-i migrate` is run with a v1 config file
- **THEN** the output SHALL contain valid v2 syntax

#### Scenario: eval with --fact flags

- **WHEN** `may-i eval` is run with --fact flags
- **THEN** the evaluation SHALL use the provided facts in decision-making

#### Scenario: missing config file

- **WHEN** MAYI_CONFIG points to a nonexistent file
- **THEN** the exit code SHALL be non-zero with a descriptive error

#### Scenario: hook with --json output

- **WHEN** the hook is invoked with --json flag
- **THEN** the output SHALL be valid JSON

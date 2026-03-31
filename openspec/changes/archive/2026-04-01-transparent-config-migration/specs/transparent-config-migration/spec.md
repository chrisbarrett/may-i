## ADDED Requirements

### Requirement: Transparent migration fallback
When normal config parsing fails, the system SHALL attempt to migrate the config from legacy v1 syntax and retry parsing.

#### Scenario: Legacy config with wrapper forms
- **GIVEN** a config file containing `(wrapper "docker" :command+args)`
- **WHEN** `config::load()` is called
- **THEN** the config SHALL be transparently migrated
- **AND** parsing SHALL succeed with the migrated config
- **AND** a warning SHALL be printed to stderr

#### Scenario: Already migrated config
- **GIVEN** a config file containing only canonical syntax `(rule "git" :effect :allow)`
- **WHEN** `config::load()` is called
- **THEN** parsing SHALL succeed on first attempt
- **AND** no migration warning SHALL be printed

#### Scenario: Invalid config that cannot be migrated
- **GIVEN** a config file with unrecoverable syntax errors `(invalid (`
- **WHEN** `config::load()` is called
- **THEN** the original parse error SHALL be returned
- **AND** the migration error SHALL NOT be returned

### Requirement: Warning message on transparent migration
When transparent migration is applied, the system SHALL print a warning to stderr.

#### Scenario: Migration applied during eval command
- **GIVEN** a legacy config file
- **WHEN** `may-i eval "git status"` is executed
- **THEN** the command SHALL succeed
- **AND** stderr SHALL contain "Config auto-migrated from legacy format"
- **AND** stderr SHALL contain "Run `may-i migrate` to update permanently"

#### Scenario: Migration applied during check command
- **GIVEN** a legacy config file
- **WHEN** `may-i check` is executed
- **THEN** the command SHALL succeed
- **AND** stderr SHALL contain the migration warning

### Requirement: Span preservation through migration
Error messages SHALL report source locations from the original config file, not the migrated text.

#### Scenario: Error in migrated config reports original location
- **GIVEN** a legacy config with 147 lines containing `(wrapper ...)` at line 147
- **AND** the migration transforms the wrapper to canonical syntax
- **WHEN** a semantic error occurs (e.g., undefined reference)
- **THEN** the error message SHALL reference line 147
- **AND** the error context SHALL show the original `(wrapper ...)` syntax

#### Scenario: Parse error in unmodified section
- **GIVEN** a legacy config with syntax error at line 50
- **WHEN** parsing fails at that location
- **THEN** the error message SHALL reference line 50
- **AND** the error context SHALL match the original file content

### Requirement: API compatibility
The public `config::load()` API SHALL remain unchanged.

#### Scenario: Existing code continues to work
- **GIVEN** existing code calling `config::load(&path)`
- **WHEN** the code is recompiled
- **THEN** no API changes SHALL be required
- **AND** the behavior SHALL include transparent migration

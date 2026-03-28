## ADDED Requirements

### Requirement: Migration operates on sexprs before AST parsing
The migration system SHALL transform configuration files by applying rewrite passes to the sexpr tree, before the AST parser processes them.

#### Scenario: Rewrite pass transforms v1 syntax
- **GIVEN** a config file containing v1 syntax `(rule (command git) (effect :allow))`
- **WHEN** the migration system runs
- **THEN** the sexpr rewrite pass SHALL transform it to v2 syntax before AST parsing

### Requirement: Each version bump adds a rewrite pass
Each DSL version transition SHALL be implemented as a discrete sexpr rewrite pass. Passes SHALL be composable so a config from any version runs through the full chain.

#### Scenario: Config from earliest version migrates to current
- **GIVEN** a config written in the earliest supported DSL version
- **WHEN** running migration
- **THEN** all rewrite passes SHALL execute in sequence
- **AND** the output SHALL be valid current-version syntax

#### Scenario: Already-current config is unchanged
- **GIVEN** a config already in the current DSL version
- **WHEN** running migration
- **THEN** no rewrite passes SHALL modify the config
- **AND** the system SHALL report no changes needed

### Requirement: CST roundtrip preserves comments and formatting
Sexpr rewrite passes SHALL use the CST representation to preserve comments, whitespace, and formatting in the output file.

#### Scenario: Comments survive migration
- **GIVEN** a config with inline comments between forms
- **WHEN** running migration
- **THEN** comments SHALL appear in the output file at their original locations

#### Scenario: Formatting is preserved for unchanged forms
- **GIVEN** a config with custom indentation and line breaks
- **WHEN** running migration
- **THEN** forms that are not rewritten SHALL retain their original formatting

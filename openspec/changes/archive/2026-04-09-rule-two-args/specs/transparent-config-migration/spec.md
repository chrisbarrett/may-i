## MODIFIED Requirements

### Requirement: Transparent migration fallback
When normal config parsing fails, the system SHALL attempt to migrate the config from legacy v1 syntax and retry parsing. The migrated output SHALL conform to the two-argument rule syntax `(rule COMMAND EFFECT)`. (CHANGED: migration output must produce single-effect rules)

#### Scenario: Legacy config with wrapper forms
- **GIVEN** a config file containing `(wrapper "docker" :command+args)`
- **WHEN** `config::load()` is called
- **THEN** the config SHALL be transparently migrated
- **AND** parsing SHALL succeed with the migrated config
- **AND** a warning SHALL be printed to stderr

#### Scenario: Already migrated config
- **GIVEN** a config file containing only canonical syntax `(rule "git" (effect :allow))`
- **WHEN** `config::load()` is called
- **THEN** parsing SHALL succeed on first attempt
- **AND** no migration warning SHALL be printed

#### Scenario: Invalid config that cannot be migrated
- **GIVEN** a config file with unrecoverable syntax errors `(invalid (`
- **WHEN** `config::load()` is called
- **THEN** the original parse error SHALL be returned
- **AND** the migration error SHALL NOT be returned

#### Scenario: Legacy rule with args and effect migrates to single effect
- **GIVEN** a config file containing `(rule (command "git") (args (positional "push")) (effect :ask))`
- **WHEN** `config::load()` is called
- **THEN** the migrated rule SHALL have a single body effect wrapping the pattern and terminal in a combinator
- **AND** parsing SHALL succeed

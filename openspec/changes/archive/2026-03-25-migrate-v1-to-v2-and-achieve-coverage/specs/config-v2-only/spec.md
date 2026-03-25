## ADDED Requirements

### Requirement: v2-only config format
The config crate SHALL support only v2 configuration format.

#### Scenario: No v1 config support
- **WHEN` v1 configuration files are loaded
- **THEN** appropriate errors indicate v1 is not supported
- **AND** migration guidance is provided

#### Scenario: v2 config loads successfully
- **WHEN** valid v2 configuration is loaded
- **THEN** it parses correctly
- **AND** all v2 features work as expected

### Requirement: Config module structure
The config crate SHALL expose only v2 modules publicly.

#### Scenario: Public v2 exports
- **WHEN** `use may_i_config::v2::*` is used
- **THEN** all v2 types are available
- **AND** no v1 types are exposed

#### Scenario: No v1 re-exports
- **WHEN** the `crates/config/src/lib.rs` is examined
- **THEN** no v1 modules are re-exported
- **AND** `pub mod v2` is the only public module

### Requirement: Config validation
The config crate SHALL validate all configuration inputs.

#### Scenario: Valid config passes
- **WHEN** a well-formed v2 config is validated
- **THEN** validation succeeds

#### Scenario: Invalid config fails
- **WHEN** a malformed v2 config is validated
- **THEN** validation returns detailed errors

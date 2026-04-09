## ADDED Requirements

### Requirement: MAYI_CONFIG env var errors on missing file
When the `MAYI_CONFIG` environment variable is set to a path that does not exist, the tool SHALL exit with a descriptive error instead of silently falling through to the default config.

#### Scenario: MAYI_CONFIG points to nonexistent file
- **WHEN** `MAYI_CONFIG` is set to a path that does not exist
- **THEN** the tool SHALL exit with code 2 and print an error message containing the path

#### Scenario: MAYI_CONFIG points to existing file
- **WHEN** `MAYI_CONFIG` is set to a path that exists
- **THEN** the tool SHALL load the config from that path (unchanged behavior)

#### Scenario: MAYI_CONFIG is unset
- **WHEN** `MAYI_CONFIG` is not set
- **THEN** the tool SHALL fall through to XDG/default config path (unchanged behavior)

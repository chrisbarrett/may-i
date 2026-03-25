## ADDED Requirements

### Requirement: Archive directory removal
The `archive/v1/` directory SHALL be completely removed.

#### Scenario: Archive directory deleted
- **WHEN** `ls archive/` is executed
- **THEN** the directory does not exist or is empty
- **AND** no v1 code remains in the working tree

#### Scenario: No references to archive
- **WHEN** the codebase is searched for `archive/v1`
- **THEN** no references are found
- **AND** build scripts do not reference archive paths

### Requirement: v1 code removal from active codebase
All v1 compatibility code SHALL be removed from active source files.

#### Scenario: No v1 imports
- **WHEN** active source files are searched for v1 module imports
- **THEN** no results are found

#### Scenario: No v1 feature flags
- **WHEN** `Cargo.toml` files are examined
- **THEN** no v1-specific features exist
- **AND** no conditional compilation for v1

#### Scenario: No v1 documentation
- **WHEN** documentation is examined
- **THEN** no references to v1 APIs remain
- **AND** migration guides point to v2 exclusively

### Requirement: Clean build verification
The project SHALL build successfully after v1 removal.

#### Scenario: Clean build passes
- **WHEN** `cargo clean && cargo build --workspace` is executed
- **THEN** build completes without errors
- **AND** no warnings about unused v1 code

#### Scenario: Test suite passes
- **WHEN** `cargo test --workspace` is executed
- **THEN** all tests pass
- **AND** no test failures related to missing v1 code

### Requirement: Dead code elimination
Any code made dead by v1 removal SHALL be identified and removed.

#### Scenario: No unused code warnings
- **WHEN** `cargo build` is run with warnings enabled
- **THEN** no "unused" warnings for previously v1-only code

#### Scenario: Code review for orphans
- **WHEN** code review is performed
- **THEN** all orphaned functions/modules are identified
- **AND** decisions made on removal or retention

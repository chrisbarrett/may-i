## ADDED Requirements

### Requirement: 90% line coverage across all workspace crates
The test suite SHALL achieve minimum 90% line coverage for every crate in the workspace.

#### Scenario: Coverage meets threshold
- **WHEN** `cargo tarpaulin --workspace` is executed
- **THEN** each crate shows ≥90% line coverage
- **AND** no crate shows <90% line coverage

### Requirement: Coverage measurement tooling
The project SHALL use tarpaulin for coverage measurement.

#### Scenario: Generate coverage report
- **WHEN** `cargo tarpaulin --workspace --out Html` is executed
- **THEN** an HTML coverage report is generated in `tarpaulin-report.html`

### Requirement: Test coverage for core evaluation logic
The engine SHALL have comprehensive tests for all evaluation paths.

#### Scenario: Test rule matching
- **WHEN** a rule matches a command
- **THEN** the evaluation returns the correct decision

#### Scenario: Test rule non-matching
- **WHEN** no rule matches a command
- **THEN** the evaluation returns Allow with no rule

#### Scenario: Test predicate evaluation
- **WHEN** predicates are evaluated against context facts
- **THEN** they return correct boolean results

#### Scenario: Test complex command structures
- **WHEN** evaluating pipelines, conditionals, and loops
- **THEN** all branches are correctly evaluated

### Requirement: Test coverage for config parsing
The config crate SHALL have tests for all parsing scenarios.

#### Scenario: Parse valid v2 config
- **WHEN** a valid v2 configuration file is loaded
- **THEN** it parses without errors

#### Scenario: Handle invalid config
- **WHEN** an invalid configuration is loaded
- **THEN** appropriate errors are returned

#### Scenario: Config migration tests
- **WHEN** legacy config migration is tested
- **THEN** all migration paths are covered

### Requirement: Test coverage for shell parsing
The shell-parser crate SHALL have tests for all parsing rules.

#### Scenario: Parse simple commands
- **WHEN** simple shell commands are parsed
- **THEN** correct AST is produced

#### Scenario: Parse complex constructs
- **WHEN** pipelines, redirects, and substitutions are parsed
- **THEN** correct AST is produced

#### Scenario: Handle parse errors
- **WHEN** invalid shell syntax is parsed
- **THEN** appropriate errors are returned

### Requirement: Test coverage for core types
The core crate SHALL have tests for all public types and traits.

#### Scenario: Test decision types
- **WHEN** Decision enum variants are used
- **THEN** all operations work correctly

#### Scenario: Test span operations
- **WHEN** source spans are manipulated
- **THEN** operations are correct

### Requirement: Test coverage for sexpr parsing
The sexpr crate SHALL have tests for all parsing scenarios.

#### Scenario: Parse valid s-expressions
- **WHEN** valid s-expressions are parsed
- **THEN** correct CST is produced

#### Scenario: Handle malformed input
- **WHEN** malformed s-expressions are parsed
- **THEN** appropriate errors are returned

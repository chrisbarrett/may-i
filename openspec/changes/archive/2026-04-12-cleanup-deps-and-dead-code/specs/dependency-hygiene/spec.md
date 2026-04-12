## ADDED Requirements

### Requirement: No unused dependencies in Cargo.toml
The root binary crate SHALL NOT declare dependencies that are unused in production or test code.

#### Scenario: Build succeeds after dependency removal
- **WHEN** unused dependencies (minus, serde) are removed from root Cargo.toml
- **THEN** `cargo build` and `cargo test` SHALL succeed without errors

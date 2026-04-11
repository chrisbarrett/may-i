## ADDED Requirements

### Requirement: Shared integration test helpers
Integration test files SHALL share common helper functions via a `tests/common/mod.rs` module rather than duplicating them.

#### Scenario: Helper functions used across test files
- **WHEN** multiple integration test files need write_config or bash_payload helpers
- **THEN** they SHALL import from tests/common/mod.rs

### Requirement: Thread-safe environment variable tests
Tests that manipulate environment variables SHALL use thread-safe mechanisms (e.g., temp_env crate) rather than unsafe direct env::set_var calls.

#### Scenario: Config path tests run in parallel
- **WHEN** config path resolution tests run concurrently
- **THEN** they SHALL not interfere with each other's environment state

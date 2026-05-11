# config-load-surface Specification

## Purpose
TBD - created by archiving change deepen-loaded-config. Update Purpose after archive.
## Requirements
### Requirement: CLI consumes LoadResult directly
CLI commands and shared library modules SHALL consume
`may_i_config::LoadResult` directly as the data shape for "a config loaded
from disk plus the source metadata needed for tracing and migration
display". The codebase SHALL NOT define a structural duplicate wrapper
around `LoadResult` that adds no behaviour.

#### Scenario: No wrapper struct exists
- **WHEN** the source tree under `src/` is searched
- **THEN** there is no struct that copies `LoadResult`'s fields one-for-one
  and offers no methods or invariants of its own

#### Scenario: TracingFold accepts a LoadResult
- **WHEN** `TracingFold::from_load_result` is called with a `&LoadResult`
- **THEN** it constructs the fold without an intermediate conversion type

#### Scenario: cmd_eval / cmd_check / hook accept a LoadResult
- **WHEN** any of these commands loads its config
- **THEN** the value flowing through the function body is a `LoadResult` and
  field access (`loaded.config`, `loaded.config_path`,
  `loaded.source_text`, `loaded.pre_migration_forms`) is unmediated

### Requirement: User-facing behaviour preserved
Removing the wrapper SHALL NOT change any user-visible output, error
message, exit code, or evaluation decision. This is a structural refactor.

#### Scenario: Existing CLI integration tests pass unchanged
- **WHEN** the integration test suite runs after the wrapper is removed
- **THEN** every existing assertion passes without modification


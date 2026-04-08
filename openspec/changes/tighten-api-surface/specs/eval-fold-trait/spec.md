## MODIFIED Requirements

### Requirement: Engine-internal types are crate-private
Types and functions that are implementation details of the engine crate (ParsedCheck, parse_check_command) SHALL use `pub(crate)` visibility instead of `pub`.

#### Scenario: Internal types not accessible from outside
- **WHEN** external code attempts to use ParsedCheck or parse_check_command
- **THEN** compilation SHALL fail with a visibility error

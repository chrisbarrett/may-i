## REMOVED Requirements

### Requirement: All CLI subcommands have integration tests

**Reason**: Capability `integration-test-coverage` folded into `testing-strategy`. CLI-coverage floor is a testing-strategy invariant, not a separate capability.
**Migration**: Reference `testing-strategy` for the CLI-coverage requirement. Body and scenarios are unchanged.

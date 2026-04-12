## ADDED Requirements

### Requirement: may-i trust subcommand exists

The system SHALL provide a `may-i trust` subcommand for reviewing and approving
trust for programs with changed or new loaded content.

#### Scenario: Trust with no arguments shows status

- **WHEN** the user runs `may-i trust`
- **THEN** the system lists all programs that need approval, showing which are
  new, changed, or up-to-date

### Requirement: may-i trust approves a specific program

The user SHALL be able to approve trust for a specific program by name.

#### Scenario: Approve a single program

- **WHEN** the user runs `may-i trust "git"`
- **THEN** the system computes the current hash for `"git"`, stores it, and
  confirms approval

#### Scenario: Approve safe-env-vars

- **WHEN** the user runs `may-i trust ":safe-env-vars"`
- **THEN** the system stores the current `safe-env-vars` hash

### Requirement: may-i trust --all approves everything

The user SHALL be able to approve all pending programs at once.

#### Scenario: Approve all pending programs

- **WHEN** the user runs `may-i trust --all`
- **THEN** all programs with pending trust changes are approved

### Requirement: Trust status in JSON mode

The `may-i trust` subcommand SHALL support `--json` output.

#### Scenario: JSON trust status

- **WHEN** the user runs `may-i trust --json`
- **THEN** the output is a JSON object listing programs with their trust status
  (approved, changed, new)

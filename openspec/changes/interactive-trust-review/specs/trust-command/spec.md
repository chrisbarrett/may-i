## MODIFIED Requirements

### Requirement: may-i trust subcommand exists

The system SHALL provide a `may-i trust` subcommand for reviewing and approving
trust for programs with changed or new loaded content.

When run interactively (TTY on stdin, no `--json`) with pending rules, `may-i trust` SHALL enter per-rule interactive review directly, without first displaying the full listing. When all rules are trusted, the grouped-by-file listing is shown. Non-interactive and JSON paths are unchanged.

#### Scenario: Trust with no arguments shows status

- **WHEN** the user runs `may-i trust`
- **THEN** the system lists all programs that need approval, showing which are
  new, changed, or up-to-date

#### Scenario: Interactive with pending enters review

- **WHEN** the user runs `may-i trust` on a TTY with pending rules
- **THEN** the per-rule review flow begins immediately

#### Scenario: Interactive all-trusted shows listing

- **WHEN** the user runs `may-i trust` on a TTY with no pending rules
- **THEN** the grouped-by-file trusted listing is displayed

## ADDED Requirements

### Requirement: Integrity-repair loop is keyed on a domain action

The interactive integrity-repair flow for suspect trust-store entries SHALL classify every user decision into a domain-level repair action variant (re-approve / drop), and the loop body that dispatches on that variant SHALL be unit-testable in isolation from any terminal or prompt library. The prompting surface SHALL be swappable so that a test driver can replace it. User-visible behaviour — warning text, per-entry display, prompt wording, default selection — SHALL be unchanged. The non-interactive branch (advisory render, no prompting) SHALL remain a single function call away from the interactive branch.

#### Scenario: Loop dispatches on the repair action variant

- **WHEN** the integrity-repair loop processes a suspect entry and the user picks "re-approve"
- **THEN** the loop produces a re-approve action for that entry, applies it to the trust store, and advances to the next suspect
- **AND** when the user picks "drop" the loop produces a drop action, applies it, and advances

#### Scenario: Loop is exercised under a scripted prompt driver

- **WHEN** a unit test instantiates the integrity-repair loop with a scripted prompt driver supplying a fixed sequence of repair actions
- **THEN** the test runs without a real terminal or prompt library
- **AND** the test asserts on the sequence of trust-store mutations and on whether the store reports as modified

#### Scenario: Non-interactive branch renders advisory without prompting

- **WHEN** the integrity-repair entry point is called in a non-interactive context (no TTY, or JSON mode)
- **THEN** the function renders the integrity advisory to stderr via the existing advisory builder and returns without invoking any prompt
- **AND** the trust store is not modified

#### Scenario: Terminal flow is unchanged for the user

- **WHEN** a user runs an interactive `may-i trust` subcommand against a store with suspect entries
- **THEN** the warning headline, per-entry detail (program name, stored hash, stored form), prompt label, and confirmation messages are byte-identical to behaviour before this change

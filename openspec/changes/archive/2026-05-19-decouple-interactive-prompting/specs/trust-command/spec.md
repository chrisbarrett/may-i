## ADDED Requirements

### Requirement: Per-rule review loop is keyed on a domain action

The per-rule interactive review flow SHALL classify every user decision into a domain-level action variant (approve / block / skip / quit), and the loop body that dispatches on that variant SHALL be unit-testable in isolation from any terminal, prompt library, or pretty-printer. The terminal prompting surface SHALL be swappable so that a test driver can replace it without changing the loop. User-visible behaviour — displayed prompts, accepted keys, screen layout, summary line — SHALL be unchanged.

#### Scenario: Loop dispatches on the domain action variant

- **WHEN** the per-rule review loop processes a pending rule and the user picks "approve"
- **THEN** the loop produces an approve action for that rule, applies it to the trust store, and advances to the next pending rule
- **AND** the same dispatch holds for block, skip, and quit, with quit ending the loop without consuming remaining rules

#### Scenario: Loop is exercised under a scripted prompt driver

- **WHEN** a unit test instantiates the per-rule review loop with a scripted prompt driver supplying a fixed sequence of answers
- **THEN** the test runs without a real terminal, prompt library, or process subshell
- **AND** the test asserts on the sequence of trust-store mutations and on the final review summary counts

#### Scenario: Terminal flow is unchanged for the user

- **WHEN** the user runs `may-i trust` interactively against pending rules
- **THEN** the displayed prompts, single-key bindings (y / n / s / q), screen-clear sequence, progress separator, trusted-summary line, and final summary are byte-identical to behaviour before this change

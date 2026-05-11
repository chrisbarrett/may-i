# Interactive-Trust-Review Specification

## Purpose

The interactive review flow for `may-i trust`: how pending rules are
presented one-per-screen with a cleared terminal, and the action keys that
drive approve / ignore / skip decisions.

Trust-relevant: yes — see `trust-command`, `trust-hashing`.

## Requirements

### Requirement: Screen-cleared per-rule review flow

When `may-i trust` enters interactive review, each pending rule SHALL be presented on a cleared terminal screen. The screen SHALL be cleared before rendering each rule.

#### Scenario: Screen clears between rules

- **WHEN** the user presses `y`, `n`, or `s` on a rule
- **THEN** the terminal is cleared and the next pending rule is displayed

#### Scenario: First rule also clears

- **WHEN** `interactive_review` begins with pending rules
- **THEN** the terminal is cleared before displaying the first rule

### Requirement: Trusted summary line always visible

Each review screen SHALL display a summary of already-trusted rules at the top, before the progress separator. The summary shows the count of trusted rules and the number of distinct source files.

#### Scenario: Summary with trusted rules

- **WHEN** 12 rules are trusted across 3 files and 5 are pending
- **THEN** the top of each review screen shows "12 rules trusted across 3 files"

#### Scenario: Summary with no trusted rules

- **WHEN** all rules are pending (none trusted)
- **THEN** no trusted summary line is displayed

### Requirement: Progress counter in HRule separator

Each review screen SHALL display progress as an HRule separator with a label showing the current position, total pending count, and status badge (NEW or CHANGED).

#### Scenario: Progress display

- **WHEN** viewing the 3rd of 5 pending rules, which is new
- **THEN** the separator reads like `──── Rule 3/5 ── NEW ──`

#### Scenario: Changed rule badge

- **WHEN** viewing a rule whose canonical form differs from the previously stored version
- **THEN** the badge in the separator is "CHANGED" in red

### Requirement: Pretty-printed rule forms in review

The rule form displayed during interactive review SHALL be pretty-printed using the pp crate's indentation engine, not shown as a flat single-line canonical string.

#### Scenario: Multi-line rule display

- **WHEN** reviewing a rule with canonical form `(rule "git" (when (fact? :env "prod") (effect :allow "safe")))`
- **THEN** the form is displayed with proper indentation across multiple lines

#### Scenario: Simple rule stays single-line

- **WHEN** reviewing a rule with canonical form `(rule "echo" (effect :allow))`
- **THEN** the form is displayed on a single line (fits within width)

### Requirement: Pretty-printed diff for changed rules

When a rule is CHANGED, both the old and new forms SHALL be pretty-printed before computing the line-level diff. Diff lines use `-`/`+` prefixes with red/green coloring.

#### Scenario: Changed rule diff display

- **WHEN** a rule changed from `(rule "kubectl" (effect :allow))` to `(rule "kubectl" (when on-vpn (effect :allow)))`
- **THEN** the diff shows pretty-printed old lines with `-` prefix in red and pretty-printed new lines with `+` prefix in green

### Requirement: Direct entry to review from list_status

When `may-i trust` (no arguments) is run interactively and pending rules exist, the system SHALL skip the full listing dump and enter per-rule review directly.

#### Scenario: Interactive with pending skips dump

- **WHEN** `may-i trust` is run on a TTY with pending rules
- **THEN** the per-rule review flow begins immediately without first showing the full listing

#### Scenario: Non-interactive still dumps

- **WHEN** `may-i trust` is run with piped stdin or `--json`
- **THEN** the full listing is displayed as before (no behavior change)

#### Scenario: All trusted shows listing

- **WHEN** `may-i trust` is run interactively with no pending rules
- **THEN** the grouped-by-file trusted listing is shown (no review flow entered)

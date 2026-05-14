---
audience: user
bucket: trust
trust-relevant: true
---
# trust-command Specification

## Purpose

The `may-i trust` CLI subcommand and its full user surface: per-rule
interactive review flow, listing approved and pending programs grouped by
source file, approving individual programs or all pending entries, the
per-rule approve/skip prompt, and `--json` output.

See related trust specs: `trust-store` for hash storage and provenance,
`trust-hashing` for what the stored hash covers, `trust-gate` for runtime
enforcement.

## Requirements

### Requirement: may-i trust subcommand exists

The system SHALL provide a `may-i trust` subcommand for reviewing and approving trust for programs with changed or new loaded content.

When run interactively (TTY on stdin, no `--json`) with pending rules, `may-i trust` SHALL enter per-rule interactive review directly, without first displaying the full listing. When all rules are trusted, the grouped-by-file listing is shown. Non-interactive and JSON paths are unchanged.

#### Scenario: Trust with no arguments shows status

- **WHEN** the user runs `may-i trust`
- **THEN** the system lists all programs that need approval, showing which are new, changed, or up-to-date

#### Scenario: Interactive with pending enters review

- **WHEN** the user runs `may-i trust` on a TTY with pending rules
- **THEN** the per-rule review flow begins immediately

#### Scenario: Interactive all-trusted shows listing

- **WHEN** the user runs `may-i trust` on a TTY with no pending rules
- **THEN** the grouped-by-file trusted listing is displayed

### Requirement: may-i trust approves a specific program

The user SHALL be able to approve trust for a specific program by name.

#### Scenario: Approve a single program

- **WHEN** the user runs `may-i trust "git"`
- **THEN** the system computes the current hash for `"git"`, stores it, and confirms approval

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
- **THEN** the output is a JSON object listing programs with their trust status (approved, changed, new)

### Requirement: Trust listing groups by file when all trusted

When all loaded programs are trusted, `may-i trust` SHALL display a two-column layout grouping program names by their source file.

#### Scenario: All programs trusted from two files

- **WHEN** `echo` and `cat` come from `~/rules/basics.lisp`, `git` comes from `~/rules/vcs.lisp`, and all are trusted
- **THEN** output shows:
  ```
    echo, cat       ~/rules/basics.lisp
    git             ~/rules/vcs.lisp

    All trusted.
  ```

#### Scenario: Single file with many programs

- **WHEN** 10 programs all come from one file and all are trusted
- **THEN** program names wrap across lines in the left column, file path on the right

### Requirement: Trust listing shows detail for untrusted programs

When NEW or CHANGED programs exist, `may-i trust` SHALL show detailed information for each untrusted program: name, status badge, source files, and canonical rule content.

#### Scenario: New untrusted program

- **WHEN** `echo` has status NEW from `~/rules/basics.lisp`
- **THEN** output shows the program name, NEW badge, source file, and the canonical rule forms

#### Scenario: Changed program shows diff

- **WHEN** `git` has status CHANGED and the trust store contains previous canonical forms
- **THEN** output shows the program name, CHANGED badge, source file, abbreviated hash transition, and a line-level diff with removed lines prefixed `-` and added lines prefixed `+`

#### Scenario: Mixed trusted and untrusted

- **WHEN** some programs are trusted and others are NEW/CHANGED
- **THEN** untrusted programs are shown with detail; trusted programs are shown in the compact grouped-by-file format

### Requirement: Interactive approval for trust operations

When run interactively (TTY on stdin, no `--json`), trust approval operations SHALL present each pending entry to the user for review before approving. This replaces blind batch approval with informed per-entry consent.

#### Scenario: `may-i trust --all` walks through each pending entry

- **WHEN** the user runs `may-i trust --all` interactively with 3 pending programs
- **THEN** for each pending program the system displays: program name, status (NEW/CHANGED), source file(s), canonical rule forms, and (for CHANGED) a diff against previously trusted forms
- **AND** the user is prompted to approve or skip each entry

#### Scenario: `may-i trust <program>` shows entry for review

- **WHEN** the user runs `may-i trust "git"` interactively and `git` is NEW or CHANGED
- **THEN** the system displays the entry detail and prompts the user to confirm approval

#### Scenario: Approved entries are saved

- **WHEN** the user approves an entry during the interactive session
- **THEN** the entry's hash and canonical forms are written to the trust store

#### Scenario: Skipped entries remain pending

- **WHEN** the user skips an entry during the interactive session
- **THEN** the entry is NOT added to the trust store and remains NEW/CHANGED on next check

#### Scenario: `may-i trust` with no args shows status then offers to approve

- **WHEN** the user runs `may-i trust` interactively and pending entries exist
- **THEN** the listing is displayed, followed by an offer to walk through pending entries for approval

#### Scenario: Non-interactive approval uses existing behavior

- **WHEN** `may-i trust --all --json` or `may-i trust --all` with piped stdin
- **THEN** all pending entries are approved without prompting (batch mode, existing behavior preserved for scripts)

#### Scenario: Already-trusted program needs no confirmation

- **WHEN** the user runs `may-i trust "echo"` and `echo` is already trusted
- **THEN** the system reports it is already trusted without prompting

### Requirement: Trust listing JSON includes metadata

In `--json` mode, the trust listing SHALL include source files, canonical forms, and previous forms for changed programs.

#### Scenario: JSON output for new program

- **WHEN** `may-i trust --json` runs with a NEW program `echo`
- **THEN** JSON includes `"program": "echo"`, `"status": "new"`, `"files": [...]`, and `"rules": [...]`

#### Scenario: JSON output for changed program

- **WHEN** `may-i trust --json` runs with a CHANGED program `git`
- **THEN** JSON includes `"previousRules": [...]` alongside current `"rules"`

#### Scenario: JSON output for trusted program

- **WHEN** `may-i trust --json` runs with all programs trusted
- **THEN** each entry includes `"status": "trusted"`, `"files"`, and `"rules"`

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

- **WHEN** reviewing a rule with canonical form `(rule "git" (when (fact? :env "prod") (allow "safe")))`
- **THEN** the form is displayed with proper indentation across multiple lines

#### Scenario: Simple rule stays single-line

- **WHEN** reviewing a rule with canonical form `(rule "echo" (allow))`
- **THEN** the form is displayed on a single line (fits within width)

### Requirement: Pretty-printed diff for changed rules

When a rule is CHANGED, both the old and new forms SHALL be pretty-printed before computing the line-level diff. Diff lines use `-`/`+` prefixes with red/green coloring.

#### Scenario: Changed rule diff display

- **WHEN** a rule changed from `(rule "kubectl" (allow))` to `(rule "kubectl" (when on-vpn (allow)))`
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

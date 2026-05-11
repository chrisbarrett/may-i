# Trust-UI-Listing Specification

## Purpose

Layout of the `may-i trust` listing: two-column grouping by source file when
all loaded programs are trusted, and alternative layouts when partial trust
state applies.

Trust-relevant: yes — see `trust-command`, `trust-store`.

## Requirements

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

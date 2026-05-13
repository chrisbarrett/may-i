---
audience: user
bucket: migration
---
# migration-diff-display Specification

## Purpose

How `may-i migrate` shows what it would change before applying: a unified text diff with a HOME-rewritten file-path header, three lines of context around each change, colour respecting `NO_COLOR`, and an interactive `[y/N]` confirmation defaulting to cancel. Non-interactive use requires `--yes` or fails with a clear message.

## Requirements

### Requirement: Migration diff shows file path header

The migration command SHALL display the config file path as a header before the diff, with the HOME directory prefix rewritten as `~`.

#### Scenario: Standard config path

- **WHEN** migrating a config at `/home/user/.config/may-i/config.lisp`
- **THEN** the diff SHALL start with `~/.config/may-i/config.lisp:`

#### Scenario: Config outside HOME

- **WHEN** migrating a config at `/etc/may-i/config.lisp`
- **THEN** the diff SHALL show the absolute path `/etc/may-i/config.lisp:`

### Requirement: Diff shows changed lines with context

The migration diff SHALL display removed lines prefixed with `-`, added lines prefixed with `+`, and unchanged context lines without prefix. It SHALL show three lines of context around each change.

#### Scenario: Changes surrounded by context

- **WHEN** a migration changes one form in a file
- **THEN** the diff includes three lines before and after the change as unchanged context

### Requirement: Diff respects NO_COLOR

The diff output SHALL use colours (red for `-`, green for `+`) when stdout is a TTY and the `NO_COLOR` environment variable is unset. With `NO_COLOR` set, colours SHALL be omitted; line prefixes still distinguish add vs remove.

#### Scenario: NO_COLOR suppresses ANSI

- **WHEN** `NO_COLOR` is set in the environment
- **THEN** the diff output contains no ANSI escape sequences

### Requirement: Migration shows diff before applying changes

The migration command SHALL display the diff before applying changes when running interactively, then prompt for confirmation with `[y/N]`.

#### Scenario: Interactive migration with changes

- **WHEN** the user runs `may-i migrate` on a config with v1 syntax in an interactive terminal and there are changes to apply
- **THEN** the command SHALL display a unified diff with file-path header and context lines
- **AND** prompt for confirmation with `[y/N]`

#### Scenario: Non-interactive with changes

- **WHEN** the user runs `may-i migrate` in a non-interactive environment with changes to apply and without `--yes`
- **THEN** the command SHALL fail with the error `Config file would be modified. Use --yes to confirm non-interactive execution.`
- **AND** not display a diff

#### Scenario: No changes needed

- **WHEN** the user runs `may-i migrate` on an already-migrated config
- **THEN** the command SHALL indicate no changes are needed
- **AND** not display a diff
- **AND** not prompt for confirmation

### Requirement: Interactive prompt defaults to No

When prompting for confirmation, the migration command SHALL default to cancelling (No) if the user presses Enter without input.

#### Scenario: User presses Enter at prompt

- **WHEN** the prompt shows `[y/N]` and the user presses Enter
- **THEN** the migration SHALL be cancelled

#### Scenario: User types 'y' at prompt

- **WHEN** the prompt shows `[y/N]` and the user types `y` or `Y`
- **THEN** the migration SHALL proceed

## ADDED Requirements

### Requirement: Migration diff shows file path header
The migration command SHALL display the config file path as a header before the diff, with the HOME directory prefix rewritten as `~`.

#### Scenario: Standard config path
- **WHEN** migrating a config at `/home/user/.config/may-i/config.lisp`
- **THEN** the diff SHALL start with `~/.config/may-i/config.lisp:`

#### Scenario: Config outside HOME
- **WHEN** migrating a config at `/etc/may-i/config.lisp`
- **THEN** the diff SHALL show the absolute path `/etc/may-i/config.lisp:`

### Requirement: Diff shows changed lines with context
The migration diff SHALL display removed lines prefixed with `-`, added lines prefixed with `+`, and unchanged context lines without prefix. It SHALL show 3 lines of context around each change.

#### Scenario: Single form change
- **WHEN** a v1 rule changes from `(rule (command git) (effect :allow))` to `(rule git :effect :allow)`
- **THEN** the diff SHALL show the old line with `-` prefix
- **AND** the new line with `+` prefix
- **AND** up to 3 lines of surrounding context without prefix

#### Scenario: Multiple changes close together
- **WHEN** two forms change near each other
- **THEN** they SHALL share context lines
- **AND** appear as one continuous diff section

### Requirement: Diff respects NO_COLOR environment variable
The diff output SHALL use colors (red for `-`, green for `+`) when stdout is a TTY and `NO_COLOR` environment variable is not set.

#### Scenario: Colored output in TTY
- **WHEN** stdout is a TTY
- **AND** `NO_COLOR` is not set
- **THEN** removed lines SHALL be red
- **AND** added lines SHALL be green

#### Scenario: Plain text when NO_COLOR set
- **WHEN** `NO_COLOR` is set to any value
- **THEN** the diff SHALL not contain ANSI color codes

#### Scenario: Plain text when piped
- **WHEN** stdout is not a TTY (e.g., piped to another command)
- **THEN** the diff SHALL not contain ANSI color codes

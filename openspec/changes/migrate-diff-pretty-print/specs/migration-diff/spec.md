## ADDED Requirements

### Requirement: Migrate command uses new diff renderer
The `may-i migrate --diff` command SHALL use the new diff rendering system.

#### Scenario: Pretty-printed diff output
- **WHEN** running `may-i migrate --diff` on a v1 config
- **THEN** the output SHALL show pretty-printed before/after forms
- **AND** the layout SHALL adapt to terminal width
- **AND** unchanged forms SHALL be collapsed with fold markers

#### Scenario: Line numbers from input file
- **WHEN** displaying the diff
- **THEN** line numbers SHALL correspond to the original input file
- **AND** the line number gutter SHALL be right-aligned

### Requirement: Built-in pager for long output
The migrate command SHALL use a built-in pager when output exceeds screen height.

#### Scenario: Pager activates for long diffs
- **WHEN** the diff output exceeds terminal height
- **THEN** the output SHALL be displayed in an interactive pager
- **AND** the pager SHALL support scrolling with arrow keys
- **AND** the pager SHALL support searching with `/`

#### Scenario: No pager for short output
- **WHEN** the diff output fits within terminal height
- **THEN** the output SHALL print directly to stdout
- **AND** no pager SHALL be invoked

#### Scenario: Pager respects terminal capabilities
- **WHEN** stdout is not a TTY
- **THEN** the pager SHALL NOT be invoked
- **AND** output SHALL print directly for piping

### Requirement: Interactive confirmation prompt
The migrate command SHALL prompt for confirmation before applying changes in interactive mode.

#### Scenario: Prompt when connected to TTY
- **WHEN** running migrate without `--yes` flag on a TTY
- **THEN** the system SHALL display the diff
- **AND** prompt "Apply migration? [Y/n] "
- **AND** only apply changes if user confirms

#### Scenario: Require --yes for non-TTY
- **WHEN** running migrate without `--yes` on a non-TTY
- **THEN** the system SHALL error with message requiring `--yes` flag
- **AND** no changes SHALL be made

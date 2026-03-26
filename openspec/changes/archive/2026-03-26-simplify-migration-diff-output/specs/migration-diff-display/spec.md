## MODIFIED Requirements

### Requirement: Migration shows diff before applying changes
The migration command SHALL display a diff showing what changes will be made before applying them when running interactively.

#### Scenario: Interactive migration with changes
- **WHEN** the user runs `may-i migrate` on a config with v1 syntax
- **AND** the terminal is interactive
- **AND** there are changes to apply
- **THEN** the command SHALL display a simplified unified diff with file path header and context lines
- **AND** prompt for confirmation with `[y/N]` prompt
- **AND** the diff format SHALL be text-based (CHANGED: previously two-column CST-based format)

#### Scenario: Non-interactive with changes
- **WHEN** the user runs `may-i migrate` in a non-interactive environment
- **AND** there are changes to apply
- **AND** the `--yes` flag is not provided
- **THEN** the command SHALL fail with error "Config file would be modified. Use --yes to confirm non-interactive execution."
- **AND** not display a diff

#### Scenario: No changes needed
- **WHEN** the user runs `may-i migrate` on an already-migrated config
- **THEN** the command SHALL indicate no changes are needed
- **AND** not display a diff
- **AND** not prompt for confirmation

### Requirement: Interactive prompt defaults to No
When prompting for confirmation, the migration command SHALL default to canceling (No) if the user just presses Enter.

#### Scenario: User presses Enter at prompt
- **WHEN** the prompt shows `[y/N]`
- **AND** the user presses Enter without typing
- **THEN** the migration SHALL be cancelled

#### Scenario: User types 'y' at prompt
- **WHEN** the prompt shows `[y/N]`
- **AND** the user types 'y' or 'Y'
- **THEN** the migration SHALL proceed

## REMOVED Requirements

### Requirement: Two-column diff layout
**Reason**: Replaced by simplified text-based unified diff format which is easier to implement and maintain
**Migration**: Users will see unified diff format instead of side-by-side before/after columns

### Requirement: Terminal width adaptation for diff layout
**Reason**: Simplified diff format handles terminal width naturally through standard text wrapping
**Migration**: No action needed; output adapts automatically

### Requirement: Fold markers for unchanged content
**Reason**: Unified diff uses context lines instead of fold markers
**Migration**: Users will see standard context lines (3 lines before/after changes)

### Requirement: Count changed forms in error message
**Reason**: Text diff operates on lines, not forms; count is not meaningful
**Migration**: Error message now says "Config file would be modified" instead of "Migration would modify N form(s)"

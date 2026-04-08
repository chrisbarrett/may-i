## ADDED Requirements

### Requirement: Eval reads command from stdin when piped
The `eval` subcommand SHALL read the shell command from stdin when stdin is not a terminal and no positional command argument is provided.

#### Scenario: Command piped via stdin
- **WHEN** stdin is not a terminal AND no positional `command` argument is given
- **THEN** the system reads stdin to EOF (up to 64KB), trims whitespace, and evaluates the result as the command

#### Scenario: Command via positional argument (TTY)
- **WHEN** stdin is a terminal AND a positional `command` argument is given
- **THEN** the system evaluates the positional argument (existing behaviour, unchanged)

### Requirement: Ambiguous input detection
The system SHALL reject ambiguous input where both stdin and argv provide a command.

#### Scenario: Both stdin and positional argument provided
- **WHEN** stdin is not a terminal AND a positional `command` argument is given
- **THEN** the system exits with an error: "ambiguous input: command provided both as argument and on stdin"

### Requirement: Missing input detection
The system SHALL reject invocations where no command is available from either source.

#### Scenario: TTY with no argument
- **WHEN** stdin is a terminal AND no positional `command` argument is given
- **THEN** the system exits with an error indicating a command is required

#### Scenario: Empty stdin
- **WHEN** stdin is not a terminal AND no positional `command` argument is given AND stdin is empty or whitespace-only
- **THEN** the system exits with an error indicating a command is required

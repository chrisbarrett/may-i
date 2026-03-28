## ADDED Requirements

### Requirement: Code execution visitor identifies dangerous commands
The code execution visitor SHALL identify and flag commands that execute arbitrary code.

#### Scenario: Detect eval command
- **WHEN** the visitor encounters an `eval` command
- **THEN** it SHALL mark the command as potentially dangerous

#### Scenario: Detect command substitution in arguments
- **WHEN** the visitor encounters command substitution $(...) or backticks in arguments
- **THEN** it SHALL flag the containing command

#### Scenario: Detect source/ dot command
- **WHEN** the visitor encounters a `source` or `.` command
- **THEN** it SHALL flag the command as loading external code

### Requirement: Function call visitor tracks function definitions and calls
The function call visitor SHALL track function definitions and their invocations.

#### Scenario: Identify function definitions
- **WHEN** the visitor encounters a function definition
- **THEN** it SHALL record the function name and body location

#### Scenario: Identify function calls
- **WHEN** the visitor encounters a simple command that matches a defined function
- **THEN** it SHALL record the function invocation

#### Scenario: Track nested functions
- **WHEN** the visitor encounters a function defined inside another function
- **THEN** it SHALL correctly track both definitions separately

### Requirement: Read builtin visitor identifies input operations
The read builtin visitor SHALL identify and analyze read operations and their variable targets.

#### Scenario: Detect read command
- **WHEN** the visitor encounters a `read` command
- **THEN** it SHALL identify the target variables

#### Scenario: Detect read with options
- **WHEN** the visitor encounters `read -p "prompt" VAR`
- **THEN** it SHALL extract both the prompt and variable name

#### Scenario: Detect read array
- **WHEN** the visitor encounters `read -a array`
- **THEN** it SHALL identify the array target

### Requirement: Wrapper unwrap visitor identifies wrapper patterns
The wrapper unwrap visitor SHALL identify wrapper commands like sudo, ssh, docker that wrap other commands.

#### Scenario: Detect sudo wrapper
- **WHEN** the visitor encounters a `sudo` command
- **THEN** it SHALL identify the wrapped command and its arguments

#### Scenario: Detect ssh wrapper
- **WHEN** the visitor encounters an `ssh` command with remote command
- **THEN** it SHALL identify the remote command being executed

#### Scenario: Detect docker exec wrapper
- **WHEN** the visitor encounters `docker exec` or `docker run`
- **THEN** it SHALL identify the container and command being run

#### Scenario: Handle nested wrappers
- **WHEN** the visitor encounters nested wrappers like `sudo ssh host cmd`
- **THEN** it SHALL identify the complete wrapper chain and innermost command

### Requirement: Visitor modules handle edge cases correctly
All visitor modules SHALL handle edge cases gracefully without panicking.

#### Scenario: Empty AST
- **WHEN** a visitor is run on an empty command
- **THEN** it SHALL complete without error and return empty results

#### Scenario: Deeply nested structures
- **WHEN** a visitor encounters deeply nested subshells or control structures
- **THEN** it SHALL traverse the entire tree without stack overflow

#### Scenario: Malformed AST nodes
- **WHEN** a visitor encounters malformed or incomplete AST nodes
- **THEN** it SHALL skip the node or use sensible defaults rather than panic

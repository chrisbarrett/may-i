## ADDED Requirements

### Requirement: Bare hook mode selects a harness adapter before evaluation
When `may-i` is invoked without a subcommand and receives JSON on stdin, it SHALL choose the supported harness adapter that matches the incoming payload before evaluating the command.

#### Scenario: Claude Code payload routes to the Claude adapter
- **WHEN** the payload matches the Claude Code hook shape, including `tool_name` and `tool_input.command`
- **THEN** `may-i` uses the Claude Code harness adapter

#### Scenario: Unknown payloads do not guess a harness
- **WHEN** the payload matches no registered harness adapter
- **THEN** `may-i` exits non-zero with a diagnostic instead of guessing a harness

### Requirement: Harness adapters extract commands and explicit runtime facts
The selected harness adapter SHALL translate only explicit payload metadata into the command and context facts passed into evaluation.

#### Scenario: Claude adapter extracts Claude Code facts from payload metadata
- **WHEN** a Claude Code payload includes fields such as `permission_mode`, `cwd`, `tool_name`, and `hook_event_name`
- **THEN** evaluation receives the command from `tool_input.command`
- **AND** evaluation receives `:client/claude-code` plus any corresponding Claude Code scalar facts present in the payload

### Requirement: Harness adapters render harness-native decision responses
After evaluation, the selected harness adapter SHALL encode the resulting decision and reason into the response format required by that harness.

#### Scenario: Claude adapter preserves the Claude Code hook response contract
- **WHEN** evaluation completes for a Claude Code payload
- **THEN** stdout contains the Claude Code `hookSpecificOutput` response with the evaluated decision and reason

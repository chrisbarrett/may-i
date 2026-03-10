## ADDED Requirements

### Requirement: Bare hook mode selects a harness adapter before evaluation
When `may-i` is invoked without a subcommand and receives JSON on stdin, it SHALL choose the supported harness adapter that matches the incoming payload before evaluating the command.

#### Scenario: Claude Code payload routes to the Claude adapter
- **WHEN** the payload matches the Claude Code hook shape, including `tool_name` and `tool_input.command`
- **THEN** `may-i` uses the Claude Code harness adapter

#### Scenario: OpenCode payload routes to the OpenCode adapter
- **WHEN** the payload matches the OpenCode hook shape and includes a command to evaluate
- **THEN** `may-i` uses the OpenCode harness adapter

#### Scenario: `OPENCODE=1` acts only as a routing hint
- **WHEN** the payload shape is otherwise ambiguous and the environment contains `OPENCODE=1`
- **THEN** `may-i` prefers the OpenCode harness adapter
- **AND** `OPENCODE=1` does not add any policy facts by itself

#### Scenario: Unknown payloads do not guess a harness
- **WHEN** the payload matches neither supported harness and no routing hint resolves it
- **THEN** `may-i` exits non-zero with a diagnostic instead of guessing a harness

### Requirement: Harness adapters extract commands and explicit runtime facts
The selected harness adapter SHALL translate only explicit payload metadata into the command and context facts passed into evaluation.

#### Scenario: Claude adapter extracts Claude Code facts from payload metadata
- **WHEN** a Claude Code payload includes fields such as `permission_mode`, `cwd`, `tool_name`, and `hook_event_name`
- **THEN** evaluation receives the command from `tool_input.command`
- **AND** evaluation receives `:client/claude-code` plus any corresponding Claude Code scalar facts present in the payload

#### Scenario: OpenCode adapter extracts OpenCode facts from payload metadata
- **WHEN** an OpenCode payload explicitly identifies the active agent as `plan`
- **THEN** evaluation receives the payload command
- **AND** evaluation receives `:client/opencode`
- **AND** evaluation receives `:opencode/agent = "plan"`

#### Scenario: Missing OpenCode agent metadata leaves the agent fact absent
- **WHEN** an OpenCode payload does not include explicit agent metadata
- **THEN** evaluation still receives `:client/opencode`
- **AND** evaluation does not receive `:opencode/agent`

### Requirement: Harness adapters render harness-native decision responses
After evaluation, the selected harness adapter SHALL encode the resulting decision and reason into the response format required by that harness.

#### Scenario: Claude adapter preserves the Claude Code hook response contract
- **WHEN** evaluation completes for a Claude Code payload
- **THEN** stdout contains the Claude Code `hookSpecificOutput` response with the evaluated decision and reason

#### Scenario: OpenCode adapter preserves the OpenCode hook response contract
- **WHEN** evaluation completes for an OpenCode payload
- **THEN** stdout contains the OpenCode response envelope with the same evaluated decision and reason

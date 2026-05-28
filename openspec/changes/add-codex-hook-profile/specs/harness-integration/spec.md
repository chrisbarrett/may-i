## MODIFIED Requirements

### Requirement: Claude Code hook reads JSON from stdin and evaluates a command

When the binary is invoked with no subcommand and stdin is not a TTY, it SHALL enter hook mode, read a JSON object from stdin containing a `tool_input` field with a `command` string, and select a harness profile from the parsed payload. If the payload object contains a `turn_id` key the profile is **Codex**; otherwise the profile is **Claude Code**. Under either profile the hook evaluates the command against the loaded config and writes a JSON response to stdout.

#### Scenario: Payload without turn_id selects the Claude Code profile

- **GIVEN** stdin contains `{"tool_name": "Bash", "tool_input": {"command": "git status"}}` with no `turn_id` key
- **WHEN** the binary is invoked with no subcommand and stdin is not a TTY
- **THEN** it SHALL evaluate `git status` against the config under the Claude
  Code profile
- **AND** write a JSON response with the decision to stdout

#### Scenario: Payload with turn_id selects the Codex profile

- **GIVEN** stdin contains `{"tool_name": "Bash", "tool_input": {"command": "git status"}, "turn_id": "t-42"}`
- **WHEN** the binary is invoked with no subcommand and stdin is not a TTY
- **THEN** it SHALL evaluate `git status` against the config under the Codex
  profile
- **AND** write a JSON response with the decision to stdout

#### Scenario: Non-bash tool is ignored

- **GIVEN** stdin contains `{"tool_name": "read_file", "tool_input": {"path": "/etc/passwd"}}`
- **WHEN** the binary is invoked in hook mode under either profile
- **THEN** it SHALL exit with status 0 and produce no output

### Requirement: Claude Code hook creates client and tool facts

Under the Claude Code profile, the hook SHALL automatically insert the facts
`:client/claude-code` (presence) and `:tool/bash` (presence) into the
evaluation context before evaluation. It SHALL NOT insert `:client/codex` under
this profile.

#### Scenario: Facts available to rules

- **GIVEN** a config with `(rule "rm" (when (fact? :client/claude-code) (deny)) :effect (allow))`
- **WHEN** the hook evaluates `rm foo` under the Claude Code profile
- **THEN** the rule SHALL match the `fact?` predicate and return Deny

#### Scenario: Claude Code fact is absent under the Codex profile

- **WHEN** the hook evaluates a command under the Codex profile
- **THEN** the evaluation context SHALL NOT include `:client/claude-code`

## ADDED Requirements

### Requirement: Codex hook creates client and tool facts

Under the Codex profile, the hook SHALL automatically insert the facts
`:client/codex` (presence) and `:tool/bash` (presence) into the evaluation
context before evaluation. When the stdin payload carries `permission_mode`,
`cwd`, `tool_name`, or `hook_event_name` fields, the hook SHALL also insert
the corresponding `:codex/permission-mode`, `:codex/cwd`, `:codex/tool-name`,
and `:codex/hook-event-name` facts.

#### Scenario: Codex client fact is present

- **GIVEN** a config with `(rule "rm" (when (fact? :client/codex) (deny)) :effect (allow))`
- **WHEN** the hook evaluates `rm foo` under the Codex profile
- **THEN** the rule SHALL match the `fact?` predicate and return Deny

#### Scenario: Codex payload fields populate namespaced facts

- **GIVEN** stdin contains
  `{"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/repo", "permission_mode": "auto"}`
- **WHEN** the hook evaluates `ls` under the Codex profile
- **THEN** the evaluation context SHALL include `:codex/cwd` = `{"/repo"}`
- **AND** the evaluation context SHALL include `:codex/permission-mode` = `{"auto"}`

### Requirement: Codex hook response shape for allow and deny

The hook SHALL, under the Codex profile, when the evaluated decision is `allow` or `deny`, emit the same response envelope as the Claude Code profile — a single JSON object with `hookSpecificOutput.hookEventName` set to `"PreToolUse"`, `hookSpecificOutput.permissionDecision` set to the decision verb, and `hookSpecificOutput.permissionDecisionReason` set to the reason string.

#### Scenario: Allow decision under Codex

- **GIVEN** the loaded config returns `(allow "safe")` for `ls`
- **WHEN** the hook emits its response under the Codex profile
- **THEN** stdout SHALL be a JSON object whose
  `hookSpecificOutput.permissionDecision` is `"allow"`
- **AND** whose `hookSpecificOutput.permissionDecisionReason` is `"safe"`

#### Scenario: Deny decision under Codex

- **GIVEN** the loaded config returns `(deny "dangerous")` for `rm -rf /`
- **WHEN** the hook emits its response under the Codex profile
- **THEN** stdout SHALL be a JSON object whose
  `hookSpecificOutput.permissionDecision` is `"deny"`
- **AND** whose `hookSpecificOutput.permissionDecisionReason` is `"dangerous"`

### Requirement: Codex hook response shape for ask

Under the Codex profile, when the evaluated decision is `ask`, the hook SHALL
emit a JSON object whose `hookSpecificOutput.hookEventName` is `"PreToolUse"`,
SHALL NOT include `hookSpecificOutput.permissionDecision`, and SHALL NOT
include `hookSpecificOutput.permissionDecisionReason`. When the rule supplies
a reason string, the hook SHALL place that string under
`hookSpecificOutput.additionalContext`; when no reason is supplied, it SHALL
omit `additionalContext`.

#### Scenario: Ask with reason

- **GIVEN** the loaded config returns `(ask "needs review")` for `curl example.com`
- **WHEN** the hook emits its response under the Codex profile
- **THEN** stdout SHALL be a JSON object whose `hookSpecificOutput.hookEventName`
  is `"PreToolUse"`
- **AND** which SHALL contain `hookSpecificOutput.additionalContext` set to
  `"needs review"`
- **AND** which SHALL NOT contain `hookSpecificOutput.permissionDecision`
- **AND** which SHALL NOT contain `hookSpecificOutput.permissionDecisionReason`

#### Scenario: Ask with no reason

- **GIVEN** the loaded config returns `(ask)` for `make build`
- **WHEN** the hook emits its response under the Codex profile
- **THEN** stdout SHALL be a JSON object whose only populated key under
  `hookSpecificOutput` is `hookEventName` set to `"PreToolUse"`

### Requirement: Codex hook trust block uses the Codex ask response shape

The hook SHALL, under the Codex profile, when the prelude trust gate blocks evaluation with an `ask` decision (because loaded rules are untrusted), emit the same shape defined in "Codex hook response shape for ask" — with the trust-block reason carried in `hookSpecificOutput.additionalContext` and no `permissionDecision` / `permissionDecisionReason` keys.

#### Scenario: Trust block under Codex

- **GIVEN** the loaded config contains untrusted rules for the input command
- **AND** the trust gate produces an `ask` block with reason
  `"Untrusted rules for echo. Run: may-i trust"`
- **WHEN** the hook emits its response under the Codex profile
- **THEN** stdout SHALL be a JSON object whose
  `hookSpecificOutput.additionalContext` contains the trust-block reason
- **AND** which SHALL NOT contain `hookSpecificOutput.permissionDecision`

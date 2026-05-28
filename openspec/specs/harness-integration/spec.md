---
audience: user
bucket: cli
---
# harness-integration Specification

## Purpose

The umbrella harness-input contract: how external agent harnesses hand a command (and optional context) to `may-i` and consume its response. Claude Code is one adapter — the `may-i` hook-mode entry point reading a JSON tool-use envelope from stdin, evaluating the bash command, and emitting a JSON response (or blocking via exit code 2 for non-bash tool calls' silent no-op). OpenCode is another adapter — `may-i eval` ingests explicit OpenCode-agent context via `--fact` flags. Generic stdin command-reading on `may-i eval` is the third surface. The hook entry — like `eval` and `check` — consumes a `CommandPipeline` (see `command-pipeline`) so config loading, terminal detection, and Trust consultation are not re-implemented per surface. See `CONTEXT.md` for hook-mode positioning within the invocation-modes table.

## Requirements

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

### Requirement: Claude Code hook resolves named predicates before evaluation

The hook SHALL call `validate_and_resolve` on the loaded config before
evaluation, ensuring that `(define ...)` predicates are inlined.

#### Scenario: Config with define works in hook mode

- **GIVEN** a config with `(define is-cc (fact? :client/claude-code))` and a
  rule `(rule "rm" (when is-cc (deny)) :effect (allow))`
- **WHEN** the hook evaluates `rm foo`
- **THEN** `is-cc` SHALL be resolved and the rule SHALL return Deny

#### Scenario: Config with unresolvable reference reports error

- **GIVEN** a config with a rule using `(when nonexistent (allow))`
- **WHEN** the hook attempts to evaluate
- **THEN** it SHALL report a resolution error rather than panicking

### Requirement: Claude Code hook uses shell parser for command splitting

The hook SHALL use the `shell_parser::parse` function to split the command
string into program name and arguments, rather than naive whitespace splitting.

#### Scenario: Quoted arguments are preserved

- **GIVEN** stdin contains a command `echo "hello world"`
- **WHEN** the hook parses the command
- **THEN** the argument list SHALL contain `hello world` as a single argument,
  not split into `"hello` and `world"`

#### Scenario: Glob characters are not expanded

- **GIVEN** stdin contains a command `ls *.rs`
- **WHEN** the hook parses the command
- **THEN** the argument list SHALL contain `*.rs` as a literal argument

### Requirement: Eval ingests explicit OpenCode agent context

When `may-i eval` is invoked with explicit OpenCode runtime facts, the evaluator SHALL expose those facts as namespaced context facts during rule matching.

#### Scenario: Explicit OpenCode facts are exposed as context facts

- **WHEN** `may-i eval` runs with `--fact :client/opencode --fact :opencode/agent=plan`
- **THEN** the evaluation context includes `:client/opencode`
- **AND** the evaluation context includes `:opencode/agent` = `{"plan"}`

#### Scenario: Missing explicit OpenCode metadata produces no OpenCode facts

- **WHEN** `may-i eval` runs without OpenCode `--fact` flags
- **THEN** the evaluation context does not include `:client/opencode`
- **AND** the evaluation context does not include `:opencode/agent`

#### Scenario: Ambient environment does not synthesize OpenCode facts

- **WHEN** `may-i eval` runs without OpenCode `--fact` flags and the shell environment contains `MAYI_OPENCODE_AGENT=plan` or `OPENCODE=1`
- **THEN** the evaluation context does not include `:client/opencode`
- **AND** the evaluation context does not include `:opencode/agent`

### Requirement: OpenCode context can gate rule evaluation

Rules SHALL be able to use `(fact? …)` predicates to match against OpenCode runtime facts supplied explicitly on the `eval` path.

#### Scenario: Rule matches a specific OpenCode agent

- **WHEN** a rule includes `(when (fact? [:opencode/agent "plan"]) …)` and `may-i eval` runs with `--fact :client/opencode --fact :opencode/agent=plan`
- **THEN** that rule's predicate matches

#### Scenario: Rule does not match a different OpenCode agent

- **WHEN** a rule includes `(when (fact? [:opencode/agent "plan"]) …)` and `may-i eval` runs with `--fact :client/opencode --fact :opencode/agent=build`
- **THEN** the predicate does not match and evaluation continues

### Requirement: OpenCode context remains inspectable in eval output

`may-i eval` SHALL preserve traceability for OpenCode-gated decisions so users can understand when explicit OpenCode runtime facts affected the result.

#### Scenario: JSON eval includes context-aware trace details

- **WHEN** `may-i --json eval` matches or skips a rule because of `:opencode/agent` supplied via explicit `--fact` flags
- **THEN** the JSON response includes trace data that reflects the fact-based evaluation

#### Scenario: Human-readable eval reflects the same decision

- **WHEN** `may-i eval` is run with explicit OpenCode facts that change which rule matches
- **THEN** the reported decision and trace output reflect the same fact-aware evaluation as JSON mode

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

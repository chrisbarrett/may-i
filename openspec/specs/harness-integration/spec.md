---
audience: user
bucket: cli
---
# Harness-Integration Specification

## Purpose

The umbrella harness-input contract: how external agent harnesses hand a command (and optional context) to `may-i` and consume its response. Claude Code is one adapter — the `may-i` hook-mode entry point reading a JSON tool-use envelope from stdin, evaluating the bash command, and emitting a JSON response (or blocking via exit code 2 for non-bash tool calls' silent no-op). OpenCode is another adapter — `may-i eval` ingests explicit OpenCode-agent context via `--fact` flags. Generic stdin command-reading on `may-i eval` is the third surface. See `CONTEXT.md` for hook-mode positioning within the invocation-modes table.

## Requirements

### Requirement: Claude Code hook reads JSON from stdin and evaluates a command

When the binary is invoked with no subcommand and stdin is not a TTY, it SHALL
enter Claude Code hook mode. The hook reads a JSON object from stdin containing
a `tool_input` field with a `command` string. It evaluates that command against
the loaded config and writes a JSON response to stdout.

#### Scenario: Valid tool input produces evaluation result

- **GIVEN** stdin contains `{"tool_name": "bash", "tool_input": {"command": "git status"}}`
- **WHEN** the binary is invoked with no subcommand and stdin is not a TTY
- **THEN** it SHALL evaluate `git status` against the config
- **AND** write a JSON response with the decision to stdout

#### Scenario: Non-bash tool is ignored

- **GIVEN** stdin contains `{"tool_name": "read_file", "tool_input": {"path": "/etc/passwd"}}`
- **WHEN** the binary is invoked in hook mode
- **THEN** it SHALL exit with status 0 and produce no output

### Requirement: Claude Code hook creates client and tool facts

When evaluating in hook mode, the hook SHALL automatically insert the facts
`:client/claude-code` (presence) and `:tool/bash` (presence) into the
evaluation context before evaluation.

#### Scenario: Facts available to rules

- **GIVEN** a config with `(rule "rm" (when (fact? :client/claude-code) (effect :deny)) :effect (effect :allow))`
- **WHEN** the hook evaluates `rm foo`
- **THEN** the rule SHALL match the `fact?` predicate and return Deny

### Requirement: Claude Code hook resolves named predicates before evaluation

The hook SHALL call `validate_and_resolve` on the loaded config before
evaluation, ensuring that `(define ...)` predicates are inlined.

#### Scenario: Config with define works in hook mode

- **GIVEN** a config with `(define is-cc (fact? :client/claude-code))` and a
  rule `(rule "rm" (when is-cc (effect :deny)) :effect (effect :allow))`
- **WHEN** the hook evaluates `rm foo`
- **THEN** `is-cc` SHALL be resolved and the rule SHALL return Deny

#### Scenario: Config with unresolvable reference reports error

- **GIVEN** a config with a rule using `(when nonexistent (effect :allow))`
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

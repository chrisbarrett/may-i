## ADDED Requirements

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

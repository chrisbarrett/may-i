## ADDED Requirements

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

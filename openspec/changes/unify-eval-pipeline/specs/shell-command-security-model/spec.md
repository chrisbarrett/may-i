## ADDED Requirements

### Requirement: Unified evaluation entry point

All entry points (hook mode, `eval --json`, `eval` pretty) SHALL use a single
`evaluate_command` function that parses the input, decomposes the AST, evaluates
all simple commands and embedded substitutions, and returns an aggregate
decision.

#### Scenario: Hook path evaluates compound command

- **WHEN** the Claude Code hook receives `echo hello && rm -rf /`
- **AND** the config has `(rule "echo" (effect :allow))` but no rule for `rm`
- **THEN** the decision SHALL be `:ask` with reason mentioning `rm`

#### Scenario: JSON and non-JSON paths agree

- **WHEN** `eval --json` and `eval` (pretty) are given the same compound input
- **THEN** both SHALL return the same decision

#### Scenario: Pipe commands are independently evaluated

- **WHEN** the input is `echo hello | rm -rf /`
- **AND** `echo` is allowed but `rm` has no rule
- **THEN** the decision SHALL be `:ask`

### Requirement: AST-based command decomposition

The evaluator SHALL walk the parsed `Command` AST to extract every simple
command, recursing into all compound structures. Every branch of every
conditional SHALL be evaluated.

#### Scenario: Subshell commands are evaluated

- **WHEN** the input is `(echo hello && rm -rf /)`
- **AND** `echo` is allowed but `rm` has no rule
- **THEN** the decision SHALL be `:ask`

#### Scenario: If-then body is evaluated

- **WHEN** the input is `if true; then rm -rf /; fi`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny`

#### Scenario: For loop body is evaluated

- **WHEN** the input is `for x in /; do rm $x; done`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny`

#### Scenario: Case arm bodies are evaluated

- **WHEN** the input is `case $x in a) rm -rf /;; b) echo hi;; esac`
- **AND** `rm` is denied, `echo` is allowed
- **THEN** the decision SHALL be `:deny` (all arms are evaluated)

#### Scenario: Both sides of OR are evaluated

- **WHEN** the input is `false || rm -rf /`
- **AND** `rm` is denied
- **THEN** the decision SHALL be `:deny`

### Requirement: Embedded command evaluation

Commands embedded in substitutions (`$(...)`, `` `...` ``, `<(...)`, `>(...)`)
within argument word parts SHALL be recursively parsed and evaluated. Their
decisions SHALL contribute to the aggregate.

#### Scenario: Command substitution in argument

- **WHEN** the input is `echo $(rm -rf /)`
- **AND** `echo` is allowed, `rm` is denied
- **THEN** the decision SHALL be `:deny`

#### Scenario: Backtick substitution in argument

- **WHEN** the input is `` echo `rm -rf /` ``
- **AND** `echo` is allowed, `rm` is denied
- **THEN** the decision SHALL be `:deny`

#### Scenario: Process substitution

- **WHEN** the input is `diff <(ls /a) <(ls /b)`
- **AND** `diff` and `ls` are both allowed
- **THEN** the decision SHALL be `:allow`

#### Scenario: Nested substitutions

- **WHEN** the input is `echo $(echo $(rm -rf /))`
- **AND** `echo` is allowed, `rm` is denied
- **THEN** the decision SHALL be `:deny`

#### Scenario: Substitution as command name

- **WHEN** the input is `$(which python) --version`
- **AND** `which` is allowed
- **THEN** the outer command decision SHALL be `:ask` (dynamic command name)
- **AND** the embedded `which` SHALL be evaluated as `:allow`

### Requirement: Dynamic command name detection

When the command name (first word of a simple command) contains dynamic parts
that cannot be resolved at parse time, the evaluator SHALL return `:ask` with a
descriptive reason.

#### Scenario: Parameter as command name

- **WHEN** the input is `$EDITOR file.txt`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL mention the dynamic parameter

#### Scenario: Glob as command name

- **WHEN** the input is `./bin/* --help`
- **THEN** the decision SHALL be `:ask`

#### Scenario: Static quoted command name

- **WHEN** the input is `"echo" hello`
- **THEN** the command name SHALL be `echo` (quotes are static)
- **AND** evaluation SHALL proceed normally

### Requirement: Empty and whitespace input handling

Empty or whitespace-only input SHALL never produce `:allow`.

#### Scenario: Empty string

- **WHEN** the input is `""`
- **THEN** the decision SHALL be `:ask` with reason mentioning empty command

#### Scenario: Whitespace only

- **WHEN** the input is `"   "`
- **THEN** the decision SHALL be `:ask`

### Requirement: Aggregate decision is most restrictive

The final decision for compound commands SHALL be the maximum over all
per-command decisions, using the ordering Allow < Ask < Deny.

#### Scenario: Mixed allow and deny

- **WHEN** the input is `echo hello; rm -rf /`
- **AND** `echo` is allowed, `rm` is denied
- **THEN** the aggregate decision SHALL be `:deny`

#### Scenario: All commands allowed

- **WHEN** the input is `echo a && echo b | cat`
- **AND** `echo` and `cat` are both allowed
- **THEN** the aggregate decision SHALL be `:allow`

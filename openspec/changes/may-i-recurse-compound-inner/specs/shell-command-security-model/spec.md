## ADDED Requirements

### Requirement: `(may-i ...)` recurses into compound inner commands

When `Effect::MayI` is evaluated, the engine SHALL re-parse the joined inner
arguments as a full shell command, decompose them into evaluation units
(simple commands, embedded substitutions), and evaluate each unit against the
configured rules. The aggregate decision SHALL be the most-restrictive across
all inner units (Allow < Ask < Deny), matching the top-level evaluator's
worst-case semantics.

#### Scenario: Inner command contains `&&` with denied arm

- **GIVEN** a rule `(rule "wrapper" (positional . (may-i *)))`
- **AND** a rule that denies `rm`
- **WHEN** the input is `wrapper "echo hi && rm -rf /"`
- **THEN** the decision SHALL be `:deny`
- **AND** the trace SHALL show both `echo` and `rm` being evaluated under the
  wrapper

#### Scenario: Inner command is a compound `if`/`then`/`fi`

- **GIVEN** a rule `(rule "wrapper" (positional . (may-i *)))`
- **AND** a rule that denies `rm`
- **WHEN** the input is `wrapper "if true; then rm -rf /; fi"`
- **THEN** the decision SHALL be `:deny`

#### Scenario: Inner command is a single simple command (regression)

- **GIVEN** a rule `(rule "wrapper" (positional . (may-i *)))`
- **AND** a rule that allows `echo`
- **WHEN** the input is `wrapper "echo hi"`
- **THEN** the decision SHALL be `:allow`

#### Scenario: Dynamic inner command name asks

- **GIVEN** a rule `(rule "wrapper" (positional . (may-i *)))`
- **WHEN** the input is `wrapper "$X arg"`
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL mention dynamic command name resolution

### Requirement: `:via` fact propagates across compound inner units

When `Effect::MayI` recurses, every inner evaluation unit SHALL see the
wrapper command name as the value of the `:via` fact, regardless of how many
units the compound inner produces.

#### Scenario: `:via` is set for each unit of a pipeline

- **GIVEN** a rule `(rule "sudo" (positional . (may-i *)))`
- **AND** a rule `(rule "echo" (when (fact? [:via "sudo"]) (effect :allow "via sudo")))`
- **WHEN** the input is `sudo echo hi | echo bye`
- **THEN** both `echo` evaluations SHALL match the via-`sudo` arm
- **AND** the decision SHALL be `:allow`

### Requirement: Recursion depth bounds the `(may-i ...)` recursion

Each `Effect::MayI` recursion SHALL count as one level toward
`recursion_limit`. Multiple inner units within a single recursion SHALL NOT
each consume a depth level.

#### Scenario: Nested wrappers hit the depth limit

- **GIVEN** a rule `(rule "wrap" (positional . (may-i *)))`
- **AND** an input where `wrap` is repeated more times than the depth limit
- **WHEN** the input is evaluated
- **THEN** the decision SHALL be `:ask`
- **AND** the reason SHALL mention the depth limit

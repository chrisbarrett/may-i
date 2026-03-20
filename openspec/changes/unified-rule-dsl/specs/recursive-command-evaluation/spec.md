## ADDED Requirements

### Requirement: (may-i PATTERN) evaluates inner commands recursively
The DSL SHALL support `(may-i PATTERN)` as an effect that matches remaining arguments as an inner command and recursively evaluates it.

#### Scenario: Simple recursive evaluation
- **WHEN** a rule contains `(may-i *)` and matches `ssh host git status`
- **THEN** the system SHALL evaluate `git status` as a separate command

#### Scenario: Recursive evaluation with pattern restriction
- **WHEN** a rule contains `(may-i (command "git"))` and matches `wrapper git status`
- **THEN** the system SHALL only recurse if the inner command is "git"

#### Scenario: Empty match in optional context
- **WHEN** `(may-i *)` is in an optional position and matches zero arguments
- **THEN** the system SHALL skip recursion and apply the outer rule's effect

#### Scenario: Non-matching may-i
- **WHEN** `(may-i PATTERN)` does not match any arguments
- **THEN** the system SHALL implicitly return `:ask` (no matching rule)

### Requirement: Dot syntax denotes remaining arguments
The DSL SHALL support `.` syntax to indicate which arguments become the recursive evaluation target.

#### Scenario: Dot syntax in positional
- **WHEN** a rule contains `(positional [:host *] . (may-i *))`
- **THEN** the first argument is captured as `:host` and remaining args are recursively evaluated

#### Scenario: Dot syntax in anywhere
- **WHEN** a rule contains `(anywhere "--command" . (may-i *))`
- **THEN** arguments after "--command" are recursively evaluated

### Requirement: Recursion depth is limited
The system SHALL enforce a configurable recursion depth limit to prevent infinite loops.

#### Scenario: Default depth limit
- **WHEN** recursive evaluation exceeds 10 levels
- **THEN** the system SHALL return `:ask` with a reason indicating depth limit exceeded

#### Scenario: Configurable depth limit
- **WHEN** the system is configured with a different depth limit
- **THEN** that limit SHALL be enforced instead of the default

### Requirement: Most restrictive effect wins
When combining effects from outer rule and recursive evaluation, the system SHALL apply the most restrictive decision.

#### Scenario: Outer allow, inner deny
- **WHEN** outer rule returns `:allow` and inner evaluation returns `:deny`
- **THEN** the final decision SHALL be `:deny`

#### Scenario: Outer allow, inner ask
- **WHEN** outer rule returns `:allow` and inner evaluation returns `:ask`
- **THEN** the final decision SHALL be `:ask`

#### Scenario: Outer ask, inner allow
- **WHEN** outer rule returns `:ask` and inner evaluation returns `:allow`
- **THEN** the final decision SHALL be `:ask`

#### Scenario: Both allow
- **WHEN** both outer rule and inner evaluation return `:allow`
- **THEN** the final decision SHALL be `:allow`

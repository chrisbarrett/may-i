## MODIFIED Requirements

### Requirement: Command pattern is an effect
The first argument to `rule` SHALL be treated as a command selector that must match the command name for the rule to apply. The selector is restricted to `Literal`, `Regex`, and `Or` forms. It is NOT a general effect — it gates whether the rule applies before body effects are considered. (CHANGED: previously described as a general effect; now explicitly a restricted selector)

#### Scenario: Command literal matches
- **GIVEN** rule `(rule "git" :effect (effect :allow))`
- **WHEN** evaluating command `"git"`
- **THEN** it SHALL return Allow

#### Scenario: Command literal doesn't match
- **GIVEN** rule `(rule "git" :effect (effect :allow))`
- **WHEN** evaluating command `"cargo"`
- **THEN** the rule SHALL not apply

#### Scenario: Command or pattern
- **GIVEN** rule `(rule (or "git" "gh") :effect (effect :allow))`
- **WHEN** evaluating command `"gh"`
- **THEN** it SHALL return Allow

#### Scenario: Command regex pattern
- **GIVEN** rule `(rule (regex "^git") :effect (effect :allow))`
- **WHEN** evaluating command `"git-lfs"`
- **THEN** it SHALL return Allow

#### Scenario: Complex expressions rejected in command position
- **GIVEN** an attempt to use `(positional ...)` as the first argument to `rule`
- **WHEN** parsing the config
- **THEN** the parser SHALL reject it with an error indicating only Literal, Regex, and Or are valid command selectors

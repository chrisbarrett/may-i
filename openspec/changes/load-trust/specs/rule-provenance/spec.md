## ADDED Requirements

### Requirement: Rules are tagged with provenance

Every `Rule` in the parsed config SHALL carry a `Provenance` value: either
`PrimaryConfig` (from the root config file) or `Loaded` (from a file included
via `(load ...)`).

#### Scenario: Root config rules are PrimaryConfig

- **WHEN** a rule is defined in the root config file
- **THEN** the rule's provenance is `PrimaryConfig`

#### Scenario: Loaded file rules are Loaded

- **WHEN** a rule is defined in a file included via `(load "rules.lisp")`
- **THEN** the rule's provenance is `Loaded`

#### Scenario: Recursively loaded rules are Loaded

- **WHEN** `a.lisp` is loaded from the root config, and `a.lisp` loads
  `b.lisp` which contains a rule
- **THEN** the rule from `b.lisp` has provenance `Loaded`

### Requirement: Defines are tagged with provenance

Every `Define` in the parsed config SHALL carry a `Provenance` value, following
the same rules as rule provenance.

#### Scenario: Root config defines are PrimaryConfig

- **WHEN** a define is in the root config file
- **THEN** the define's provenance is `PrimaryConfig`

#### Scenario: Loaded file defines are Loaded

- **WHEN** a define is in a file included via `(load ...)`
- **THEN** the define's provenance is `Loaded`

### Requirement: CommandPattern::Regex is removed

The system SHALL NOT accept regex patterns in command dispatch position. The
`CommandPattern` type SHALL only support `Literal` and `Or` variants.

#### Scenario: Regex in command position is a parse error

- **WHEN** config contains `(rule (regex "^git-.*") (allow))`
- **THEN** the parser reports an error

#### Scenario: Literal command patterns still work

- **WHEN** config contains `(rule "git" (allow))`
- **THEN** the rule parses successfully

#### Scenario: Or command patterns still work

- **WHEN** config contains `(rule (or "cat" "head" "tail") (allow))`
- **THEN** the rule parses successfully

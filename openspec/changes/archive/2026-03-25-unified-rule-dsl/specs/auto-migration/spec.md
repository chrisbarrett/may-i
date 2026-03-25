## ADDED Requirements

### Requirement: Migration tool converts old rule syntax
The auto-migration tool SHALL convert v1 rule syntax to v2 syntax.

#### Scenario: Simple rule migration
- **GIVEN** a v1 rule `(rule (command "git") (args (positional "push")) (effect :ask))`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce `(rule "git" (positional "push") (effect :ask))`

#### Scenario: Rule with context
- **GIVEN** a v1 rule `(rule (command "git") (context (has :via/ssh)) (effect :allow))`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce `(rule "git" (has :via/ssh) (effect :allow))`

#### Scenario: Rule with combined context and args
- **GIVEN** a v1 rule with both `(context ...)` and `(args ...)`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce a rule with `(and ...)` combining both

### Requirement: Migration tool converts wrappers to rules
The auto-migration tool SHALL convert wrapper definitions to rules with `(may-i ...)`.

#### Scenario: Simple wrapper
- **GIVEN** a v1 wrapper `(wrapper "ssh" (positional [:host *] :command+args))`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce `(rule "ssh" (positional [:host *] . (may-i *)) (effect :allow))`

#### Scenario: Wrapper with multiple steps
- **GIVEN** a v1 wrapper with multiple steps
- **WHEN** the migration tool runs
- **THEN** it SHALL produce an appropriate rule with `(may-i ...)`

### Requirement: Migration tool converts defcontext to define
The auto-migration tool SHALL convert `defcontext` to `define`.

#### Scenario: Simple defcontext
- **GIVEN** a v1 `(defcontext remote-prod (and (has :via/ssh) (has [:host (regex "^prod-")])))`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce `(define remote-prod (and (has :via/ssh) (has [:host (regex "^prod-")])))`

### Requirement: Migration tool handles cond in args
The auto-migration tool SHALL convert `(args (cond ...))` to `(case ...)` at the effect level.

#### Scenario: Args cond migration
- **GIVEN** a v1 `(args (cond ((positional "push") (effect :ask)) (else (effect :deny))))`
- **WHEN** the migration tool runs
- **THEN** it SHALL produce `(case ((positional "push") (effect :ask)) (else (effect :deny)))` as the rule's effect

### Requirement: Migration tool preserves check forms
The auto-migration tool SHALL preserve check forms unchanged.

#### Scenario: Check preservation
- **GIVEN** v1 check forms `(check :allow "cmd")` or `(with-facts [...] :allow "cmd")`
- **WHEN** the migration tool runs
- **THEN** these SHALL be preserved in the output

### Requirement: Migration produces valid v2 syntax
The auto-migration tool SHALL only produce syntactically valid v2 configs.

#### Scenario: Validation of output
- **WHEN** the migration tool produces output
- **THEN** the output SHALL parse successfully with the v2 parser

### Requirement: Migration reports unhandled cases
The auto-migration tool SHALL report any constructs it cannot automatically migrate.

#### Scenario: Unhandled construct
- **GIVEN** a v1 construct with no v2 equivalent
- **WHEN** the migration tool runs
- **THEN** it SHALL report the unhandled case with location information

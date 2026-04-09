## ADDED Requirements

### Requirement: Compound v1 forms preserve evaluation semantics
Migration of v1 configs that trigger multiple rewrite rules simultaneously SHALL produce v2 configs that evaluate identically for all input commands, arguments, and facts.

#### Scenario: Command + context + args combined
- **WHEN** a v1 rule has (command ...), (context ...), and (args ...) forms
- **THEN** the migrated v2 rule SHALL produce the same allow/deny/ask decision for any input

#### Scenario: Named predicate references
- **WHEN** a v1 config uses (defcontext NAME ...) referenced in (context NAME)
- **THEN** the migrated config with (define NAME ...) SHALL evaluate identically

#### Scenario: Compound context with nested has key-value
- **WHEN** a v1 context uses (and (has :key) (has [:key value]))
- **THEN** the migrated fact? expressions SHALL match the same inputs

### Requirement: Real-world wrapper patterns migrate correctly
All wrapper form patterns used in production configs SHALL be tested through migration.

#### Scenario: Wrapper with positional + flag + capture
- **WHEN** a wrapper like (wrapper "mise" (positional "exec") (flag "--" :command+args)) is migrated
- **THEN** the resulting rule SHALL evaluate identically for wrapped commands

#### Scenario: Flag-only wrapper
- **WHEN** a wrapper like (wrapper "nix-shell" (flag "--run" :command+args)) is migrated
- **THEN** the resulting rule SHALL evaluate identically

### Requirement: has with complex value patterns migrates correctly
The rename_has_to_fact rewrite SHALL preserve semantics for all legal value patterns.

#### Scenario: has with regex value
- **WHEN** (has [:key (regex "pattern")]) is migrated
- **THEN** (fact? [:key (regex "pattern")]) SHALL match the same inputs

#### Scenario: has with or value
- **WHEN** (has [:key (or "a" "b")]) is migrated
- **THEN** (fact? [:key (or "a" "b")]) SHALL match the same inputs

### Requirement: Mixed v1/v2 configs migrate correctly
Files containing both v1 and v2 syntax SHALL only migrate the v1 forms, leaving v2 forms unchanged.

#### Scenario: Mixed syntax file
- **WHEN** a config has both (rule (command "git") ...) and (rule "ls" ...) forms
- **THEN** only the v1 form SHALL be rewritten; the v2 form SHALL be byte-identical

### Requirement: Proptest generators cover compound v1 forms
Property tests SHALL generate compound v1 configs and verify evaluation equivalence after migration.

#### Scenario: Random compound v1 configs
- **WHEN** arbitrary v1 configs with command+context+args are generated
- **THEN** migration SHALL always preserve evaluation semantics

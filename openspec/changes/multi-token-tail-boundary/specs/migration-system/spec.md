## ADDED Requirements

### Requirement: `strip_redundant_boundary` strips literals matching any prelude tail token

The `strip_redundant_boundary` migration pass SHALL inspect the prelude's `(tail (after STR…))` token set for the rule's program and strip any positional literal in the rule body that matches any token in that set. Programs whose prelude tail is `(after :flags)`, or whose prelude has no parser declaration, SHALL be unaffected.

#### Scenario: Single-token prelude tail strips matching literal
- **GIVEN** a prelude declaring `(parser "p" (style gnu) (tail (after "TOK")))`
- **AND** a migrated rule `(rule "p" (when (positional "X" "TOK") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL become `(rule "p" (when (positional "X") (tail (authorise))))`

#### Scenario: Multi-token prelude tail strips any matching literal
- **GIVEN** a prelude declaring `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))`
- **AND** a migrated rule `(rule "nix" (when (positional (or "shell" "develop") "--command") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL become `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`

#### Scenario: Migration of v1 nix wrapper produces correct rule
- **GIVEN** a v1 wrapper form `(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))`
- **WHEN** the full migration pipeline runs
- **THEN** the output SHALL be `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`
- **AND** the migrated rule SHALL correctly route `nix shell pkg --command mkfs /dev/sda` through `(tail (authorise))` for recursive evaluation

#### Scenario: No-op for `:after-flags` prelude tail
- **GIVEN** a prelude declaring `(parser "sudo" (style gnu) (tail (after :flags)))`
- **AND** a migrated rule `(rule "sudo" (when (positional "literal") (tail (authorise))))`
- **WHEN** the migration pipeline applies `strip_redundant_boundary`
- **THEN** the rule SHALL be unchanged (no boundary literal to strip)

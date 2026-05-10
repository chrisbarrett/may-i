## Requirements

### Requirement: Parser tail boundary accepts a single literal token

A `(parser PROG …)` form SHALL accept `(tail (after STR))` to declare a single literal boundary token. The engine SHALL split argv at the first occurrence of `STR`; the outer slice SHALL be the tokens before `STR`, the tail slice SHALL be the tokens after `STR`, and the boundary token itself SHALL be consumed (appearing in neither slice).

#### Scenario: Single-token tail boundary splits argv
- **GIVEN** a parser declaration `(parser "mise" (style gnu) (tail (after "--")))`
- **WHEN** evaluating `mise exec -- rm -rf /tmp/foo`
- **THEN** the outer slice SHALL be `[mise, exec]`
- **AND** the tail slice SHALL be `[rm, -rf, /tmp/foo]`
- **AND** the literal `--` token SHALL not appear in either slice

#### Scenario: Single-token form serialises as `(after "TOK")`
- **GIVEN** a parser whose tail is `Tail::AfterToken(vec!["--".to_string()])`
- **WHEN** rendering the parser declaration
- **THEN** the output SHALL be `(tail (after "--"))`, not `(tail (after ["--"]))`

### Requirement: Parser tail boundary accepts an alias-set of literal tokens

A `(parser PROG …)` form SHALL accept `(tail (after [STR…]))` to declare a set of literal boundary tokens that are treated as alternative spellings of the same boundary. The engine SHALL split argv at the first occurrence of any token in the set. The set SHALL contain at least one token; the empty form `(tail (after []))` SHALL be a parse-time error.

#### Scenario: Multi-token tail boundary splits at first matching spelling
- **GIVEN** a parser declaration `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))`
- **WHEN** evaluating `nix shell pkg --command mkfs /dev/sda`
- **THEN** the outer slice SHALL be `[shell, pkg]`
- **AND** the tail slice SHALL be `[mkfs, /dev/sda]`

#### Scenario: Multi-token tail boundary splits at alternative spelling
- **GIVEN** a parser declaration `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))`
- **WHEN** evaluating `nix shell pkg -c mkfs /dev/sda`
- **THEN** the outer slice SHALL be `[shell, pkg]`
- **AND** the tail slice SHALL be `[mkfs, /dev/sda]`

#### Scenario: Multi-token form serialises with brackets
- **GIVEN** a parser whose tail is `Tail::AfterToken(vec!["--command".to_string(), "-c".to_string()])`
- **WHEN** rendering the parser declaration
- **THEN** the output SHALL be `(tail (after ["--command" "-c"]))`

#### Scenario: Empty token-set is rejected
- **WHEN** parsing `(parser "x" (tail (after [])))`
- **THEN** the parser SHALL emit an error explaining at least one boundary token is required

### Requirement: `(tail (authorise))` returns no-match when boundary is absent and a tail is declared

When a parser declares a tail (via either `(after :flags)` or `(after STR…)`) and the argv does not contain the boundary, the engine SHALL treat `(tail (authorise))` in a rule body as a no-match, NOT as a recursion on the full argv. The fallback to the full argv SHALL apply only when the parser declares no tail at all.

#### Scenario: Boundary-absent argv produces no-match
- **GIVEN** a parser declaration `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))`
- **AND** a rule `(rule "nix" (when (positional (or "shell" "develop")) (tail (authorise))))`
- **WHEN** evaluating `nix shell pkg`
- **THEN** the `(tail (authorise))` matcher SHALL return no-match
- **AND** the rule SHALL not fire
- **AND** evaluation SHALL continue to subsequent rules

#### Scenario: Boundary-present argv triggers recursion
- **GIVEN** the same parser and rule as above
- **WHEN** evaluating `nix shell pkg --command mkfs /dev/sda`
- **THEN** the `(tail (authorise))` matcher SHALL recurse on `mkfs /dev/sda`
- **AND** the recursive evaluation SHALL be the rule's terminal effect

#### Scenario: No-tail parser still recurses on full argv
- **GIVEN** a rule whose program has no parser-level `(tail …)` declaration
- **AND** the rule body contains `(tail (authorise))`
- **WHEN** evaluating any argv for that program
- **THEN** the recursion SHALL operate on the full argv (existing fallback behaviour preserved)

### Requirement: Prelude declares a `nix` parser with multi-token tail boundary

The prelude SHALL ship a parser declaration for `nix` with `style gnu` and `(tail (after ["--command" "-c"]))`. User configurations SHALL be able to shadow this declaration by providing their own `(parser "nix" …)` form.

#### Scenario: Prelude `nix` parser is loaded by default
- **WHEN** a config containing only user rules is loaded (no `(parser "nix" …)` declaration)
- **THEN** the resolved parser for `nix` SHALL have `Tail::AfterToken(vec!["--command", "-c"])`

#### Scenario: User declaration shadows prelude
- **GIVEN** a user config containing `(parser "nix" (style gnu) (tail (after "--command")))`
- **WHEN** the config is loaded
- **THEN** the resolved parser for `nix` SHALL be the user's declaration
- **AND** `-c` SHALL not be treated as a boundary token

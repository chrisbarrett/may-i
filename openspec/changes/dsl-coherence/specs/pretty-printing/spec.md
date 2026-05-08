## ADDED Requirements

### Requirement: Canonical form sorts parser body declarations

The canonical form of a `(parser PROG …)` declaration SHALL sort the body's declaration forms in a fixed order:

1. `(style …)` first (always exactly one).
2. All `(flag …)` declarations next, sorted alphabetically by canonical name.
3. All `(parameter …)` declarations next, sorted alphabetically by canonical name. The canonical name of a vector-spelled parameter (e.g. `["n" "namespace"]`) SHALL be the long form when present, else the short.
4. `(tail …)` last (at most one).

The pretty-printer SHALL emit declarations in this order when rendering canonical form (used for trust hashing). User-typed source ordering MAY be preserved by the source-trivia path during transparent reformatting; only canonical form is required to sort.

#### Scenario: Parser body sorts in canonical order

- **GIVEN** `(parser "x" (tail (after :flags)) (parameter "n") (style gnu) (flag "v"))`
- **WHEN** the canonical form is computed
- **THEN** the canonical form SHALL be `(parser "x" (style gnu) (flag "v") (parameter "n") (tail (after :flags)))`.

#### Scenario: Parameter declarations sort by canonical name

- **GIVEN** `(parser "x" (style gnu) (parameter "z") (parameter ["n" "namespace"]) (parameter "a"))`
- **WHEN** the canonical form is computed
- **THEN** parameters SHALL appear in order: `(parameter "a")`, `(parameter ["n" "namespace"])`, `(parameter "z")`.

### Requirement: Canonical form sorts define-arg-style attributes

The canonical form of `(define-arg-style NAME …)` SHALL sort the body's attribute forms alphabetically by attribute-name.

#### Scenario: Define-arg-style attributes sort

- **GIVEN** `(define-arg-style java (separators " " "=" ":") (overrides gnu) (combined-shorts nil))`
- **WHEN** the canonical form is computed
- **THEN** the canonical form SHALL list attributes in alphabetical order: `(combined-shorts nil)`, `(overrides gnu)`, `(separators " " "=" ":")`.

### Requirement: Canonical form sorts check cases

The canonical form of `(check …)` SHALL sort the body's case forms alphabetically by command string.

#### Scenario: Check cases sort

- **GIVEN** `(check (deny "rm -rf /") (allow "ls -la") (ask "rm -rf /tmp/foo"))`
- **WHEN** the canonical form is computed
- **THEN** the canonical form SHALL list cases in alphabetical order: `(allow "ls -la")`, `(ask "rm -rf /tmp/foo")`, `(deny "rm -rf /")`.

### Requirement: Rule order is preserved (not sorted)

Rule order in source SHALL be preserved in canonical form. Rule order is semantic (short-circuit evaluation), so reordering would change behaviour.

#### Scenario: Rules retain source order

- **GIVEN** a config with rule A, then rule B, then rule C
- **WHEN** the canonical form is computed
- **THEN** rules SHALL appear in source order A, B, C.

## ADDED Requirements

### Requirement: Canonical body-form ordering

A pre-render canonicalisation pass SHALL apply deterministic ordering to multi-declaration bodies before the pretty-printer renders them. The canonical order is independent of source order.

**Order specification:**

- **Parser body** (`(parser PROG …)`):
    1. `(style …)` first.
    2. All `(flag …)` declarations in alphabetical order by canonical name.
    3. All `(parameter …)` declarations in alphabetical order by canonical name.
    4. `(tail …)` last.
- **`define-arg-style` body** (`(define-arg-style NAME …)`): attribute forms in alphabetical order by attribute head atom.
- **`check` body** (`(check …)`): cases in alphabetical order by their command string.
- **Rule body**: order preserved. Rule bodies use short-circuit evaluation; order is semantic and SHALL NOT be reordered.

**Canonical name extraction:**

| Form                              | Sort key                                         |
| --------------------------------- | ------------------------------------------------ |
| `(flag "X")`                      | `"X"`                                            |
| `(parameter "X" …)`               | `"X"`                                            |
| `(flag [STR…])`                   | first element of vector after vector sort        |
| `(parameter [STR…] …)`            | first element of vector after vector sort        |

#### Scenario: Parser body canonical order

- **WHEN** the canonicaliser receives `(parser "git" (parameter "C") (flag "v") (flag "version") (parameter "config") (style gnu) (tail (after :flags)))`
- **THEN** the rendered output is `(parser "git" (style gnu) (flag "v") (flag "version") (parameter "C") (parameter "config") (tail (after :flags)))`

#### Scenario: define-arg-style attributes alphabetised

- **WHEN** the canonicaliser receives `(define-arg-style mystyle (separators "=") (long-prefix "--") (overrides gnu))`
- **THEN** the rendered output is `(define-arg-style mystyle (long-prefix "--") (overrides gnu) (separators "="))`

#### Scenario: Check cases alphabetised by command

- **WHEN** the canonicaliser receives `(check (deny "rm -rf /") (allow "ls"))`
- **THEN** the rendered output is `(check (allow "ls") (deny "rm -rf /"))`

#### Scenario: Rule body order preserved

- **WHEN** the canonicaliser receives a rule with multiple body forms (e.g., `(rule "git" (positional "diff") (allow))`)
- **THEN** the body forms appear in source order in the rendered output

### Requirement: Set-vector canonicalisation

A vector that appears in the name position of `(flag VEC)` or `(parameter VEC …)` is set-typed: declaration semantics are insensitive to vector element order. The canonicaliser SHALL sort such vectors lexicographically.

Vectors elsewhere in the DSL are sequence-typed and order-significant. The canonicaliser SHALL NOT sort sequence-typed vectors. This includes (non-exhaustive): `(separators …)`, prefix lists in `define-arg-style`, and any vector inside a rule body.

#### Scenario: Flag name vector sorted

- **WHEN** the canonicaliser receives `(flag ["r" "0"])`
- **THEN** the rendered output is `(flag ["0" "r"])`

#### Scenario: Parameter name vector sorted

- **WHEN** the canonicaliser receives `(parameter ["n" "interval"])`
- **THEN** the rendered output is `(parameter ["interval" "n"])`

#### Scenario: Separator vector preserved

- **WHEN** the canonicaliser receives `(define-arg-style mystyle (separators "=" " "))`
- **THEN** the rendered output preserves separator order: `(separators "=" " ")`

### Requirement: Sort relocates form trivia atomically

When the canonicaliser reorders a form, the form's leading and trailing trivia (whitespace and comments) SHALL move with it. This is a structural property of the CST trivia model: leading trivia is owned by the next form; sort reorders form-with-trivia as a unit.

The pretty-printer SHALL preserve the moved trivia in the rendered output, subject to the existing whitespace canonicalisation rules.

#### Scenario: Comment travels with form on sort

- **WHEN** the canonicaliser receives:
  ```
  (parser "x"
    (flag "z")
    ;; about a
    (flag "a"))
  ```
- **THEN** the rendered output places the `;; about a` comment immediately before `(flag "a")`, regardless of `(flag "a")`'s new position relative to `(flag "z")`:
  ```
  (parser "x"
    ;; about a
    (flag "a")
    (flag "z"))
  ```

#### Scenario: Trailing comment in list moves with last child

- **WHEN** the canonicaliser receives:
  ```
  (parser "x"
    (flag "z")
    (flag "a")
    ;; trailing
    )
  ```
  where `;; trailing` is attached as trailing trivia of `(flag "a")` (the last child)
- **THEN** the rendered output preserves `;; trailing` as trailing trivia of `(flag "a")` in its new position

### Requirement: Canonicalisation is idempotent

Running the canonicaliser on its own output SHALL produce a structurally identical CST: `canonicalise(canonicalise(x)) ≡ canonicalise(x)`. After pretty-printing, the byte representation SHALL also be stable: `pretty(canonicalise(parse(pretty(canonicalise(parse(s)))))) == pretty(canonicalise(parse(s)))`.

#### Scenario: Canonicaliser is idempotent on arbitrary configs

- **WHEN** an arbitrary canonical-syntax config is canonicalised once and then again
- **THEN** the second pass produces a CST structurally identical to the first

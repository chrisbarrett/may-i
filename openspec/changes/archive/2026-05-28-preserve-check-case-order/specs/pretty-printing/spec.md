## MODIFIED Requirements

### Requirement: Canonical body-form ordering

A pre-render canonicalisation pass SHALL apply deterministic ordering to multi-declaration bodies before the pretty-printer renders them. A body SHALL be sorted only when **both** of the following hold; otherwise authored order SHALL be preserved verbatim:

1. **Engine-order-independent**: reordering the body's children is a semantic no-op (no short-circuit evaluation, no positional binding).
2. **Not human-curated**: the body has no convention of embedded organisation such as section-header comments or mnemonic grouping between children.

Either condition alone is sufficient to preserve order.

**Order specification:**

- **Parser body** (`(parser PROG …)`):
    1. `(style …)` first.
    2. All `(flag …)` declarations in alphabetical order by canonical name.
    3. All `(parameter …)` declarations in alphabetical order by canonical name.
    4. `(tail …)` last.
- **`define-arg-style` body** (`(define-arg-style NAME …)`): attribute forms in alphabetical order by attribute head atom.
- **`check` body** (`(check …)`): order preserved. Check cases are engine-order-independent but human-curated — users group cases under section-header comments, and the formatter SHALL NOT scramble that authored structure.
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

#### Scenario: Check cases preserve source order

- **WHEN** the canonicaliser receives `(check (deny "rm -rf /") (allow "ls"))`
- **THEN** the rendered output preserves source order: `(check (deny "rm -rf /") (allow "ls"))`

#### Scenario: Check section-header comments stay with their cases

- **WHEN** the canonicaliser receives a `(check …)` form whose body interleaves section-header comments (e.g. `;; State manipulation`) with check cases
- **THEN** each comment appears in the rendered output immediately above the same case it preceded in the source

#### Scenario: Rule body order preserved

- **WHEN** the canonicaliser receives a rule with multiple body forms (e.g., `(rule "git" (positional "diff") (allow))`)
- **THEN** the body forms appear in source order in the rendered output

## REMOVED Requirements

- **Canonical form sorts check cases** — subsumed by the revised "Canonical body-form ordering" requirement, which now specifies source-order preservation for `(check …)` bodies (cases are engine-order-independent but human-curated).

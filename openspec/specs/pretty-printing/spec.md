## Requirements

### Requirement: Indent Specification System

The pretty-printer SHALL use an indent specification system modeled after Emacs
Lisp's `(declare (indent N))` to control how form arguments are laid out. The
spec is a static table mapping head atoms to an integer N representing the
number of "special" arguments before the body.

**Interpretation of N:**
- N = 0: All children after the head are body (indent +2 from opening paren)
- N = 1: First arg is special (stays inline if fits), rest are body (+2)
- N = 2: First two args are special (first inline, second at align column),
  rest are body (+2)

**Indent Spec Table:**
| Form | N | Notes |
|------|---|-------|
| `cond` | 0 | Uses dedicated renderer (always breaks, see below) |
| `define` | 1 | Name is special, body follows |
| `if` | 2 | Pred and then-branch are special, else is body |
| `rule` | 1 | Command/pattern is special, body follows |
| `unless` | 1 | Pred is special, body follows |
| `when` | 1 | Pred is special, body follows |
| `with-facts` | 1 | Facts vector is special, body follows |

Forms not in this table use default function-call alignment.

`check` is intentionally absent: it takes keyword-value pairs in a plist-like
calling convention and reads naturally with function-call alignment (args align
under the first arg).

The `doc_from_sexpr` function SHALL be public API, converting `may_i_sexpr::Sexpr` nodes into `Doc<()>` trees suitable for pretty-printing. This enables canonical form strings to be parsed and pretty-printed outside of test contexts.

#### Scenario: N=0 form (cond)
- **WHEN** pretty-printing `(cond ((pred1) (effect :allow)) (else (effect :deny)))`
- **THEN** the form always breaks with clauses at +2 and body parts on separate lines

#### Scenario: N=1 form (when)
- **WHEN** pretty-printing `(when pred (effect :allow))` at narrow width
- **THEN** pred stays on head line if it fits, body is at +2

#### Scenario: N=2 form (if)
- **WHEN** pretty-printing `(if pred then else)`
- **THEN** pred is special-1, then-branch is special-2, else-branch is body

#### Scenario: Canonical form string round-trips through pretty-printer
- **WHEN** a canonical form string like `(rule "git" (when (fact? :env "prod") (effect :allow)))` is parsed with `may_i_sexpr::parse` and converted with `doc_from_sexpr`
- **THEN** `may_i_pp::pretty` produces properly indented multi-line output respecting indent specs

### Requirement: Cond Form Layout

The `cond` form SHALL use a dedicated renderer that always breaks clauses onto
separate lines with body parts on their own lines.

**Layout Rules:**
1. `cond` always starts on its own line (never packed)
2. Each clause is on its own line at indent +2
3. Within each clause, the predicate and each body part are on separate lines
4. Body parts within a clause are at indent +3

### Requirement: If Form Asymmetric Indentation

The `if` form SHALL use asymmetric indentation to visually distinguish the
then-branch (consequence) from the else-branch (alternative).

**Layout Rules:**
1. If the entire form fits on one line: render flat `(if p e1 e2)`
2. Otherwise:
   - Pred stays on the same line as `if` when it fits within the column width
   - Then-branch at indent +4 (aligns under pred's start column)
   - Else-branch at indent +2 (body indent)

### Requirement: Fill Layout for All-Atom Forms

Forms whose arguments are ALL atoms (strings, keywords, identifiers, regexes)
SHALL use "fill layout" instead of standard broken layout: `and`, `or`,
`forbidden`, `anywhere`, `positional`.

**Fill Layout Algorithm:**
1. Head atom on opening line
2. First arg follows head on same line
3. Subsequent args flow across lines, wrapping when next arg exceeds width
4. Wrap column is the column of the first arg
5. Multiple items may appear on each line

**Trigger Condition:**
- Head is one of: `and`, `or`, `forbidden`, `anywhere`, `positional`
- All children after head are atoms (no nested lists)

### Requirement: Function-Call Alignment

Forms not in the indent spec table SHALL use function-call alignment:
subsequent arguments align under the first argument.

**Alignment Formula:**
`align_col = paren_col + 1 + head_width + 1`

### Requirement: Special Form Keyword Coloring

The pretty-printer SHALL syntax-color the head atoms of known forms in blue.

**Colored form list:**
- All forms in the indent spec table: `check`, `cond`, `define`, `if`, `rule`,
  `unless`, `when`, `with-facts`
- Structural effect form: `effect`
- Pattern forms: `anywhere`, `exact`, `positional`
- Control forms: `else`

### Requirement: Whitespace trivia preserves blank lines
The pretty printer SHALL preserve blank lines from whitespace-only trivia when
rendering child elements.

### Requirement: Preserved children use source trivia for rendering
When `pretty_serialize` renders a list node, children that carry original source
trivia (non-zero span) SHALL be rendered via the trivia-preserving path,
emitting their original whitespace verbatim.

### Requirement: Constructed children use reflow rendering
Children that were freshly constructed by rewrite rules (zero span / default
trivia) SHALL be rendered via the whitespace-stripping path, applying the
standard reflow and indentation logic.

### Requirement: Source trivia detection via span
A node SHALL be considered to have source trivia if its annotation span is
non-zero (i.e., `span.start != 0 || span.end != 0`).

### Requirement: Whole-line comment positioning
The pretty-serializer SHALL emit whole-line comments at the current indentation
level. A comment is whole-line when the `Trivia::Whitespace` entry immediately
preceding it in the trivia vector contains a newline character.

### Requirement: Line-trailing comment preservation
The pretty-serializer SHALL preserve the exact whitespace gap before a
line-trailing comment.

### Requirement: Special-form lookup table
The classification of forms into special-form vs function-call SHALL be
determined by a static `&[&str]` lookup table in the pretty-serializer.

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

## MODIFIED Requirements

### Requirement: Migration rule `and_trailing_effect_to_when`

The migration rule SHALL extract a trailing low-complexity `(effect ...)` from
an `(and ...)` predicate, rewriting to a `(when ...)` form.

**Trigger:** `(and e1 … en)` where `en` is `(effect ...)` with structural
complexity ≤ 3.

**Complexity scoring:**
- Atoms: 1
- `(regex "r")`: 1 (special-cased as a leaf)
- Any other `(tag e1 … en)`: `1 + max(complexity(e1), …, complexity(en))`
- `[e1 … en]` (vector): `1 + max(complexity(e1), …, complexity(en))`

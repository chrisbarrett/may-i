---
audience: user
bucket: cli
---
# pretty-printing Specification

## Purpose

Defines the canonical pretty-printing rules for `may-i` configuration files: indentation, special-form layout, comment placement, declaration ordering, and round-trip stability under `may-i fmt`.
## Requirements
### Requirement: Indent Specification System

The pretty-printer SHALL use an indent specification system modeled
after Emacs Lisp's `(declare (indent N))` to control how form arguments
are laid out. The spec is a static table mapping head atoms to an
integer N representing the number of "special" arguments before the
body.

**Interpretation of N:**

- N = 0: Reserved for forms with dedicated renderers (currently only
  `cond`). The default body-indent of `+2` does not apply.
- N = 1: First arg is special (stays inline if fits), rest are body
  (`+2`)
- N = 2: First two args are special (first inline, second at align
  column), rest are body (`+2`)

**Indent Spec Table:**

| Form | N | Notes |
|------|---|-------|
| `cond` | 0 | Dedicated renderer; clause indent is `+1`, see Cond Form Layout |
| `define` | 1 | Name is special, body follows |
| `define-arg-style` | 1 | Name is special, attribute body follows |
| `if` | 2 | Pred and then-branch are special, else is body |
| `parser` | 1 | Program name is special, declaration body follows |
| `rule` | 1 | Command/pattern is special, body follows |
| `unless` | 1 | Pred is special, body follows |
| `when` | 1 | Pred is special, body follows |
| `with-facts` | 1 | Facts vector is special, body follows |

Forms not in this table use default function-call alignment (see
Cascade Discipline for Broken Layouts).

`check` is intentionally absent: it takes keyword-value pairs in a
plist-like calling convention and reads naturally with function-call
alignment (args align under the first arg).

The `doc_from_sexpr` function SHALL be public API, converting
`may_i_sexpr::Sexpr` nodes into `Doc<()>` trees suitable for
pretty-printing. This enables canonical form strings to be parsed and
pretty-printed outside of test contexts.

#### Scenario: N=0 form (cond) uses dedicated renderer

- **WHEN** pretty-printing `(cond ((pred1) (allow)) (else (deny)))`
- **THEN** the form always breaks with clauses at `+1` from the cond
  paren and body parts on separate lines at clause `+1`

#### Scenario: N=1 form (when)

- **WHEN** pretty-printing `(when pred (allow))` at narrow width
- **THEN** pred stays on head line if it fits, body is at `+2`

#### Scenario: N=2 form (if)

- **WHEN** pretty-printing `(if pred then else)`
- **THEN** pred is special-1, then-branch is special-2, else-branch is
  body

#### Scenario: Canonical form string round-trips through pretty-printer

- **WHEN** a canonical form string like `(rule "git" (when (fact? :env "prod") (allow)))`
  is parsed with `may_i_sexpr::parse` and converted with `doc_from_sexpr`
- **THEN** `may_i_pp::pretty` produces properly indented multi-line
  output respecting indent specs and cascade discipline

### Requirement: Cond Form Layout

The `cond` form SHALL use a dedicated renderer that always breaks clauses
onto separate lines with body parts on their own lines.

**Layout Rules:**

1. `cond` always starts on its own line (never packed)
2. Each clause is at indent `+1` from the opening paren of `cond`,
   matching the column where the first clause would sit if it were on
   the head line
3. Within each clause, the predicate and each body part are on separate
   lines
4. Body parts within a clause are at the clause's indent `+1`

The `+1` clause indent matches Emacs / Common-Lisp convention for forms
without a defun-style body indent. It is distinct from the `+2`
body-indent that applies to forms in the indent spec table — `cond` is
listed in that table for keyword-coloring purposes only; its clause
layout does not use the body-indent computation.

#### Scenario: Cond clauses indent at +1

- **WHEN** pretty-printing a `(cond …)` form whose enclosing parent
  places `cond` at column `C`
- **THEN** each clause's opening paren is at column `C + 1`

#### Scenario: Cond clause body parts indent at clause +1

- **WHEN** a cond clause `(PRED EFFECT)` is broken across lines
- **THEN** `EFFECT` is at the clause's column + 1, aligning under
  `PRED`

### Requirement: If Form Asymmetric Indentation

The `if` form SHALL use asymmetric indentation to visually distinguish the
then-branch (consequence) from the else-branch (alternative).

**Layout Rules:**
1. If the entire form fits on one line: render flat `(if p e1 e2)`
2. Otherwise:
   - Pred stays on the same line as `if` when it fits within the column width
   - Then-branch at indent +4 (aligns under pred's start column)
   - Else-branch at indent +2 (body indent)

#### Scenario: If form breaks asymmetrically
- **WHEN** an `(if pred then else)` form does not fit on one line
- **THEN** the then-branch is rendered at indent +4 and the else-branch at indent +2

### Requirement: Fill Layout for All-Atom Forms

The pretty-printer SHALL use "fill layout" (rather than the standard broken layout) for forms whose head is one of `and`, `or`, `forbidden`, `anywhere`, or `positional` and whose arguments are ALL atoms (strings, keywords, identifiers, regexes).

**Fill Layout Algorithm:**
1. Head atom on opening line
2. First arg follows head on same line
3. Subsequent args flow across lines, wrapping when next arg exceeds width
4. Wrap column is the column of the first arg
5. Multiple items may appear on each line

**Trigger Condition:**
- Head is one of: `and`, `or`, `forbidden`, `anywhere`, `positional`
- All children after head are atoms (no nested lists)

#### Scenario: All-atom positional uses fill layout
- **WHEN** pretty-printing `(positional "a" "b" "c" "d")` at narrow width
- **THEN** atoms flow across lines, wrapping at the first-arg column rather than one per line

### Requirement: Function-Call Alignment

Forms not in the indent spec table SHALL use function-call alignment:
subsequent arguments align under the first argument.

**Alignment Formula:**
`align_col = paren_col + 1 + head_width + 1`

#### Scenario: Default form aligns under first arg
- **WHEN** pretty-printing a form `(foo a b c)` whose head is not in the indent spec table and which breaks across lines
- **THEN** subsequent args align at column `paren_col + 1 + head_width + 1` (under the first arg)

### Requirement: Special Form Keyword Coloring

The pretty-printer SHALL syntax-color the head atoms of known forms in blue.

**Colored form list:**
- All forms in the indent spec table: `cond`, `define`, `define-arg-style`,
  `if`, `parser`, `rule`, `unless`, `when`, `with-facts`
- `check` (keyword-color only; uses function-call alignment, not in indent
  spec table)
- Structural effect form: `effect`
- Pattern forms: `anywhere`, `exact`, `positional`
- Control forms: `else`

#### Scenario: Known head atom is colored
- **WHEN** pretty-printing a form whose head atom is in the colored form list (e.g., `when`, `effect`, `positional`)
- **THEN** the head atom is emitted with the blue colour annotation

### Requirement: Whitespace trivia preserves blank lines
The pretty printer SHALL preserve blank lines from whitespace-only trivia when
rendering child elements.

#### Scenario: Blank line between children survives
- **WHEN** the source CST contains a whitespace-only trivia entry with two newlines between two child forms
- **THEN** the rendered output preserves the blank line between them

### Requirement: Preserved children use source trivia for rendering
When `pretty_serialize` renders a list node, children that carry original source trivia (non-zero span), the renderer SHALL use the trivia-preserving path and emit their original whitespace verbatim.

#### Scenario: Source-spanned child renders via preservation path
- **WHEN** a child node has a non-zero source span
- **THEN** the renderer emits its leading and inter-element whitespace verbatim from source trivia

### Requirement: Constructed children use reflow rendering
For children that were freshly constructed by rewrite rules (zero span / default trivia), the renderer SHALL use the whitespace-stripping path and apply the standard reflow and indentation logic.

#### Scenario: Zero-span child renders via reflow path
- **WHEN** a child node has a zero source span (constructed by a rewrite)
- **THEN** the renderer ignores any source-derived whitespace and applies the standard reflow and indentation rules

### Requirement: Source trivia detection via span
A node SHALL be considered to have source trivia if its annotation span is
non-zero (i.e., `span.start != 0 || span.end != 0`).

#### Scenario: Span discriminates source vs constructed
- **WHEN** the renderer inspects a node's annotation span
- **THEN** it classifies the node as source-trivia-bearing iff `span.start != 0 || span.end != 0`

### Requirement: Whole-line comment positioning
The pretty-serializer SHALL emit whole-line comments at the current indentation
level. A comment is whole-line when the `Trivia::Whitespace` entry immediately
preceding it in the trivia vector contains a newline character.

#### Scenario: Comment after newline-bearing whitespace is whole-line
- **WHEN** a comment trivia is preceded by a `Trivia::Whitespace` containing a newline
- **THEN** the comment is emitted on its own line at the current indentation level

### Requirement: Line-trailing comment preservation
The pretty-serializer SHALL preserve the exact whitespace gap before a
line-trailing comment.

#### Scenario: Trailing-comment gap preserved verbatim
- **WHEN** a line-trailing comment in the source is preceded by N spaces of whitespace
- **THEN** the rendered output emits the same N-space gap before the comment

### Requirement: Special-form lookup table
The classification of forms into special-form vs function-call SHALL be
determined by a static `&[&str]` lookup table in the pretty-serializer.

#### Scenario: Lookup table drives classification
- **WHEN** the renderer classifies a head atom
- **THEN** the decision is made by membership in a static `&[&str]` lookup table, not by dynamic computation

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

### Requirement: Cascade Discipline for Broken Layouts

The pretty-printer SHALL fix the cascade column at the start of the first
inline argument once that column is established, and MUST NOT update it as
further children attach inline. When a child must break to a new line, the
break lands at this fixed cascade column. Drift to the right with each
inline child is forbidden.

**Cascade column rules:**

- For forms in the indent spec table: cascade column is `paren_col + 2` (body
  indent), regardless of inline placement.
- For default forms (function-call alignment) where the first argument is
  placed inline on the head line: cascade column is the start column of the
  *first* inline argument. This column is computed once and never updated.
- For default forms where the first argument breaks to its own line (because
  source trivia forces it): cascade column is `paren_col + 1`.

#### Scenario: Multiple inline args before a break does not drift

- **WHEN** rendering `(positional A B C D)` where `A`, `B`, `C` fit on the
  head line but `D` does not
- **THEN** `D` breaks at the start column of `A`, not the start column of
  `C`

#### Scenario: Deeply nested forms do not accumulate drift

- **WHEN** rendering `(when (or (positional X (or "a" "b" "c" "d")) (positional Y)) (allow))`
  at a width that forces inner `or`'s last atom to wrap
- **THEN** the wrapped atom aligns under the inner `or`'s first argument,
  not at a column that depends on how many siblings preceded it

#### Scenario: Source trivia forces head-alone cascade

- **WHEN** the source has a newline immediately after the head atom, placing
  the first argument on its own line
- **THEN** the cascade column is `paren_col + 1`, matching the column of
  the (broken) first argument


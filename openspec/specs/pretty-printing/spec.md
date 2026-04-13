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

#### Scenario: N=0 form (cond)
- **WHEN** pretty-printing `(cond ((pred1) (effect :allow)) (else (effect :deny)))`
- **THEN** the form always breaks with clauses at +2 and body parts on separate lines

#### Scenario: N=1 form (when)
- **WHEN** pretty-printing `(when pred (effect :allow))` at narrow width
- **THEN** pred stays on head line if it fits, body is at +2

#### Scenario: N=2 form (if)
- **WHEN** pretty-printing `(if pred then else)`
- **THEN** pred is special-1, then-branch is special-2, else-branch is body

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

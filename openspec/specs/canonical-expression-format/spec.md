## ADDED Requirements

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
| `cond` | 0 | All clauses are body |
| `define` | 1 | Name is special, body follows |
| `if` | 2 | Pred and then-branch are special, else is body |
| `rule` | 1 | Command/pattern is special, body follows |
| `unless` | 1 | Pred is special, body follows |
| `when` | 1 | Pred is special, body follows |
| `with-facts` | 1 | Facts vector is special, body follows |

Forms not in this table use default function-call alignment.

#### Scenario: N=0 form (cond)
- **WHEN** pretty-printing `(cond ((pred1) (effect :allow)) (else (effect :deny)))`
- **THEN** all clauses are indented +2 from opening paren:
  ```
  (cond
    ((pred1) (effect :allow))
    (else (effect :deny)))
  ```

#### Scenario: N=1 form (when)
- **WHEN** pretty-printing `(when pred (effect :allow))` at narrow width
- **THEN** pred stays on head line if it fits, body is at +2:
  ```
  (when (and a b)
    (effect :allow))
  ```

#### Scenario: N=1 form with multiline special arg
- **WHEN** the first special arg exceeds width
- **THEN** it drops to align under the first arg column:
  ```
  (when
      (and xxxxxxxxxxxx
           yyyyyyyyyyyy)
    (effect :allow))
  ```

#### Scenario: N=2 form (if)
- **WHEN** pretty-printing `(if pred then else)`
- **THEN** pred is special-1, then-branch is special-2, else-branch is body:
  ```
  (if pred
      then-branch
    else-branch)
  ```

---

### Requirement: If Form Asymmetric Indentation

The `if` form SHALL use asymmetric indentation to visually distinguish the
then-branch (consequence) from the else-branch (alternative).

**Layout Rules:**
1. If the entire form fits on one line: render flat `(if p e1 e2)`
2. Otherwise:
   - Pred stays on the same line as `if` (always)
   - Then-branch is at indent +4 (aligns under pred if pred is atomic)
   - Else-branch is at indent +2 (body indent)

This creates the characteristic "staircase" indentation that makes the
asymmetry visually apparent.

#### Scenario: Single line if fits
- **WHEN** `(if pred yes no)` fits within the width
- **THEN** render as: `(if pred yes no)`

#### Scenario: Broken if form
- **WHEN** `(if pred (effect :allow "yes") (effect :deny "no"))` exceeds width
- **THEN** render with asymmetric indentation:
  ```
  (if pred
      (effect :allow "yes")
    (effect :deny "no"))
  ```

#### Scenario: Multiline condition stays inline
- **WHEN** the pred is a complex form that itself breaks across lines
- **THEN** pred opens on the same line as `if`, continues on its own lines:
  ```
  (if (or "~/.config/tmux/custom.conf"
          "~/.config/tmux/tmux.conf")
      (effect :allow "ok")
    (effect :deny "not found"))
  ```

---

### Requirement: Fill Layout for And/Or Forms

`and` and `or` forms whose arguments are ALL atoms (strings, keywords,
identifiers, regexes) SHALL use "fill layout" instead of the standard broken
layout.

**Fill Layout Algorithm:**
1. Head atom on opening line: `(and ` or `(or `
2. First arg follows head on same line
3. Subsequent args flow across lines, wrapping when the next arg would exceed
   the width limit
4. Wrap point is the column of the first arg (align under first arg)
5. Multiple items may appear on each line (unlike broken layout's one-per-line)

**Trigger Condition:**
- Head is `"and"` or `"or"`
- All children after head are atoms (no nested lists)

#### Scenario: Short and/or on one line
- **WHEN** `(and "a" "b" "c")` fits within width
- **THEN** render flat: `(and "a" "b" "c")`

#### Scenario: Fill layout wraps atoms
- **WHEN** `(or "cat" "bat" "head" "tail" "less" "ls")` exceeds width
- **THEN** atoms flow across lines:
  ```
  (or "cat" "bat" "head"
      "tail" "less" "ls")
  ```

#### Scenario: Mixed length atoms
- **WHEN** atoms have varying lengths
- **THEN** pack as many as fit on each line:
  ```
  (and "a" "bb"
       "ccc" "dddd"
       "eeeee")
  ```

#### Scenario: Non-atom args disable fill
- **WHEN** an `and` or `or` contains a nested list
- **THEN** use standard broken layout (one item per line):
  ```
  (and (anywhere "-r")
       (anywhere "/"))
  ```

---

### Requirement: Function-Call Alignment

Forms not in the indent spec table SHALL use function-call alignment:
subsequent arguments align under the first argument.

**Alignment Formula:**
```
align_col = paren_col + 1 + head_width + 1
```

Where:
- `paren_col` is the column of the opening paren
- `head_width` is the visible width of the head atom

#### Scenario: Simple function call
- **WHEN** pretty-printing `(command "git" "status")`
- **AND** it exceeds width
- **THEN** align under first arg:
  ```
  (command "git"
           "status")
  ```

#### Scenario: Long head atom
- **WHEN** the head atom is long, pushing alignment far right
- **THEN** still align at calculated column (may look awkward but consistent):
  ```
  (positional "arg1"
              "arg2")
  ```

---

### Requirement: Special Form Keyword Coloring

The pretty-printer SHALL syntax-color head atoms that are special forms.

**Coloring Rules:**
- Special forms (from indent spec table): distinct color (e.g., blue)
- All other atoms: default color

**Special Forms List:** `cond`, `define`, `effect`, `if`, `rule`, `unless`,
`when`, `with-facts`

#### Scenario: Special form head is colored
- **WHEN` rendering `(when pred body)`
- **THEN** `when` appears in special-form color

#### Scenario: Non-special form is default color
- **WHEN** rendering `(command "git")`
- **THEN** `command` appears in default color

---

## MODIFIED Requirements

### Requirement: Remove Dead Case References

The `case` form was renamed to `cond` before release. All references to `case`
in the pretty-printer SHALL be removed.

**Items to Remove:**
1. `("case", 0)` from `INDENT_SPECS` table
2. `"case"` from colored keywords list
3. `case` branch in cond/case special renderer check (now just `cond`)

#### Scenario: Cond form uses render_cond
- **WHEN** pretty-printing a `cond` form
- **THEN** it uses the dedicated `render_cond` function, not indent specs
- **AND** no `case` logic is invoked

---

### Requirement: Rename Migration Function

The migration function `args_cond_to_case` SHALL be renamed to `hoist_cond` to
accurately describe its purpose: lifting cond expressions from args position
into rule bodies.

#### Scenario: Function is renamed
- **WHEN** searching for `args_cond_to_case` in the codebase
- **THEN** no results are found
- **AND** `hoist_cond` exists and performs the same transformation

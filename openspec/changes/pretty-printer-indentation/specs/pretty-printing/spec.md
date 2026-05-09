## ADDED Requirements

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

## MODIFIED Requirements

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
| `if` | 2 | Pred and then-branch are special, else is body |
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

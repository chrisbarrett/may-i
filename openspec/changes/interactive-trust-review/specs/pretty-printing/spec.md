## MODIFIED Requirements

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

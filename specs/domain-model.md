# Domain Model

Core types forming the authorization algebra. Decision is a lattice under
`most_restrictive`. Expressions and argument matchers form a boolean algebra
verified by property-based tests.

---

## R36: Decision lattice

`Decision` is totally ordered: `Allow < Ask < Deny`.

`most_restrictive(a, b)` returns the greater value. Properties:

- **Commutative:** `most_restrictive(a, b) == most_restrictive(b, a)`
- **Associative:** `most_restrictive(most_restrictive(a, b), c) == most_restrictive(a, most_restrictive(b, c))`
- **Idempotent:** `most_restrictive(a, a) == a`
- **Identity:** `Allow` is the identity element
- **Absorbing:** `Deny` is absorbing — `most_restrictive(Deny, x) == Deny`

**Verify:** `cargo test -- decision`; property-based tests with `proptest`

## R37: Effect

An `Effect` pairs a `Decision` with an optional reason string. Effects are
produced by rules (from `(effect ...)` forms) and by `Cond` branches.

**Verify:** `cargo check`

## R38: Expression algebra

`Expr` evaluates to a boolean (match/no-match) with optional effect extraction
from `Cond` branches:

| Variant       | Semantics                              |
| :------------ | :------------------------------------- |
| `Literal(s)`  | Exact string equality                  |
| `Regex(r)`    | Regex match against full string        |
| `Wildcard`    | Always matches (including opaque args) |
| `And(exprs)`  | All must match; short-circuits on fail |
| `Or(exprs)`   | Any must match; short-circuits on pass |
| `Not(expr)`   | Inverts match; **drops effects**       |
| `Cond(arms)`  | First matching branch wins; extracts effect |

Boolean algebra properties (verified by property tests):

- **De Morgan:** `Not(And(a, b)) ≡ Or(Not(a), Not(b))` (match equivalence)
- **Double negation:** `Not(Not(a)) ≡ a` (match equivalence)
- **Commutativity:** `And(a, b) ≡ And(b, a)`, `Or(a, b) ≡ Or(b, a)`
- **Identity:** `And(a, Wildcard) ≡ a`, `Or(a, Not(Wildcard)) ≡ a`
- **Absorption:** `Or(a, Wildcard) ≡ Wildcard`, `And(a, Not(Wildcard)) ≡ Not(Wildcard)`

**Verify:** `cargo test -- expr`; `proptest` property tests

## R39: Argument matchers

`ArgMatcher` operates on argument lists (after flag expansion):

| Variant           | Semantics                                        |
| :---------------- | :----------------------------------------------- |
| `Positional`      | Match positional args (skip flags); trailing OK  |
| `ExactPositional` | Like `Positional` but requires exact arg count   |
| `Anywhere`        | Any expr matches any arg (OR semantics)          |
| `And`             | All sub-matchers must match                      |
| `Or`              | Any sub-matcher must match                       |
| `Not`             | Inverts; **drops effects**                       |
| `Cond`            | First matching branch wins; extracts effect      |

`Not` never produces effects — it returns `MatchedNoEffect` or `NoMatch`.

**Verify:** `cargo test -- matcher`; property tests

## R40: Positional quantifiers

Inside `Positional` and `ExactPositional`, each pattern has a quantifier:

| Quantifier   | Consumes                       |
| :----------- | :----------------------------- |
| `One`        | Exactly 1 arg                  |
| `Optional`   | 0 or 1 arg                     |
| `OneOrMore`  | 1+ args (greedy, no backtrack) |
| `ZeroOrMore` | 0+ args (greedy, no backtrack) |

Quantifiers consume left-to-right. Greedy quantifiers do not backtrack — they
take as many matching args as possible.

**Verify:** `cargo test -- matcher::quantifier`; property tests

## R41: Command matcher

Rules match commands by name:

| Form          | Semantics                     |
| :------------ | :---------------------------- |
| `Exact(name)` | String equality               |
| `Regex(pat)`  | Regex against command name    |
| `List(names)` | Any name in the list          |

**Verify:** `cargo test -- matcher::command`

## R42: Rule structure

A `Rule` combines a command matcher, a body, inline checks, and a source span:

- `RuleBody::Effect` — optional arg matcher + fixed effect
- `RuleBody::Branching` — arg matcher (must be `Cond`) determines effect

**Given** `RuleBody::Effect` with no arg matcher **Then** the rule matches any
args for the command — effect applies unconditionally.

**Given** `RuleBody::Effect` with an arg matcher **Then** the effect applies
only when args match.

**Given** `RuleBody::Branching` **Then** the `Cond` arg matcher's first
matching branch provides the effect. No separate `(effect ...)` form is
allowed.

**Verify:** `cargo test -- config::parse`; `may-i check`

## R43: Match outcome

Matching produces one of:

| Outcome            | Meaning                                  |
| :----------------- | :--------------------------------------- |
| `Matched(effect)`  | Matched with an extracted effect         |
| `MatchedNoEffect`  | Matched but no effect (e.g., inside Not) |
| `NoMatch`          | Did not match                            |

`MatchedNoEffect` combines with the rule's own effect. `NoMatch` means the rule
is skipped.

**Verify:** `cargo test -- matcher`

## Constraints

- `Decision` ordering must be total (used in aggregation)
- `Not` must always drop effects (safety invariant — negation flips semantics,
  so embedded effects would be misleading)
- Property tests must cover all algebraic identities

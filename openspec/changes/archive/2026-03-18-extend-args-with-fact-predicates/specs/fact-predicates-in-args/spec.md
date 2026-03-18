## ADDED Requirements

### Requirement: BoolExpr type for fact predicates
The system SHALL support a `BoolExpr` type representing fact predicates with the following variants:
- `Has(FactQuery)` - query for presence or value of a fact
- `And(Vec<BoolExpr>)` - all sub-predicates must match
- `Or(Vec<BoolExpr>)` - any sub-predicate must match
- `Not(Box<BoolExpr>)` - negates a sub-predicate

#### Scenario: Has presence check
- **WHEN** evaluating `BoolExpr::Has(FactQuery::Presence { key: ":via/ssh" })` against facts containing `:via/ssh`
- **THEN** the predicate SHALL return true

#### Scenario: Has value check with literal
- **WHEN** evaluating `BoolExpr::Has(FactQuery::Value { key: ":env", pattern: Literal("prod") })` against facts containing `[:env "prod"]`
- **THEN** the predicate SHALL return true

#### Scenario: Has value check with regex
- **WHEN** evaluating `BoolExpr::Has` with a regex pattern against a matching fact value
- **THEN** the predicate SHALL return true

#### Scenario: Boolean combinators
- **WHEN** evaluating `BoolExpr::And` with two `Has` sub-predicates where both match
- **THEN** the predicate SHALL return true

### Requirement: ArgMatcher has fact checking
The system SHALL extend `ArgMatcher` with a `Has(BoolExpr)` variant that evaluates fact predicates during argument matching.

#### Scenario: Direct has matcher
- **WHEN** matching arguments with `ArgMatcher::Has(BoolExpr::Has(...))` against matching facts
- **THEN** the matcher SHALL succeed

#### Scenario: Has in and combinator
- **WHEN** evaluating `ArgMatcher::And([Has(...), Positional(...)])` where both match
- **THEN** the matcher SHALL succeed

### Requirement: Polymorphic conditional branches
The system SHALL support `ArgMatcher::Cond` branches where each test can be:
- A full `ArgMatcher` (positional, anywhere, etc.)
- An `Expr` (inline string predicate)
- A `BoolExpr` (fact predicate)

#### Scenario: Cond with mixed predicate types
- **WHEN** evaluating a `Cond` with branches containing positional matchers, string expressions, and has checks
- **THEN** each branch SHALL evaluate according to its predicate type

#### Scenario: When with has predicate
- **WHEN** using `(when (has [:env "prod"]) (effect :deny))` in args
- **THEN** the effect SHALL apply when the fact matches

#### Scenario: Unless with positional and has
- **WHEN** using `(unless (and (has [:env "prod"]) (positional "delete")) (effect :allow))`
- **THEN** the effect SHALL apply when either predicate fails

#### Scenario: If with mixed predicates
- **WHEN** using `(if (has [:env "prod"]) (effect :deny) (effect :allow))`
- **THEN** the appropriate branch SHALL apply based on fact evaluation

### Requirement: ContextFacts threading
The system SHALL thread `ContextFacts` through all argument evaluation functions.

#### Scenario: Evaluate with context
- **WHEN** evaluating arguments with `evaluate_with_context` including runtime facts
- **THEN** has predicates SHALL have access to those facts

#### Scenario: Facts from wrappers
- **WHEN** a wrapper adds facts (e.g., `:via/ssh`, `:ssh/host`)
- **THEN** subsequent has predicates in the inner command SHALL see those facts

### Requirement: First-class sugar forms
The system SHALL preserve `when`/`unless`/`if` as first-class AST nodes (not desugared to `cond`) for trace fidelity.

#### Scenario: Trace shows when form
- **WHEN** a rule uses `(when ...)` and the trace is generated
- **THEN** the trace SHALL show `when` not `cond`

#### Scenario: Trace shows unless form
- **WHEN** a rule uses `(unless ...)` and the trace is generated
- **THEN** the trace SHALL show `unless` not `cond`

### Requirement: Backward compatibility for Expr conditionals
The system SHALL preserve existing `Expr::{Cond,When,Unless,If}` for string-level conditionals.

#### Scenario: Expr cond still works
- **WHEN** using `(positional (cond (("a" eff1) ("b" eff2))) *)` 
- **THEN** the expression SHALL evaluate as before

#### Scenario: Nested expr conditionals
- **WHEN** using `(or (when "a" eff) (unless "b" eff))` at the expression level
- **THEN** the expression SHALL evaluate as before

### Requirement: Type-safe predicate domains
The system SHALL enforce that:
- `Expr` only contains string predicates (no `has`)
- `BoolExpr` only contains fact predicates
- `ArgMatcher` can mix both via polymorphic branches

#### Scenario: Reject has in Expr and
- **WHEN** parsing `(and "literal" (has [:key]))` at the expression level
- **THEN** the parser SHALL reject it with a clear error

#### Scenario: Allow has in ArgMatcher and
- **WHEN** parsing `(and (positional "cmd") (has [:key]))` at the matcher level
- **THEN** the parser SHALL accept it

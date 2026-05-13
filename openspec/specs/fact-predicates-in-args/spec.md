---
audience: contributor
bucket: parsing
---
# fact-predicates-in-args Specification

## Purpose

Contributor-only. The internal `BoolExpr` enum the evaluator uses for fact-based predicates inside arg matching, plus the polymorphic conditional-branch typing (`(when …)`, `(unless …)`, `(if …)` accept `ArgMatcher` | `Expr` | `BoolExpr`) and the `ContextFacts` threading rule. Backing representation for the user-facing `(fact? …)` form surfaced in `facts`.

## Requirements

### Requirement: BoolExpr type for fact predicates
The system SHALL support a `BoolExpr` type representing fact predicates with the following variants: (CHANGED: `Has` renamed to `Fact` to align with `fact?` syntax)
- `Fact(FactQuery)` - query for presence or value of a fact
- `And(Vec<BoolExpr>)` - all sub-predicates must match
- `Or(Vec<BoolExpr>)` - any sub-predicate must match
- `Not(Box<BoolExpr>)` - negates a sub-predicate

#### Scenario: Fact presence check
- **WHEN** evaluating `BoolExpr::Fact(FactQuery::Presence { key: ":via" })` against facts containing `:via`
- **THEN** the predicate SHALL return true

#### Scenario: Fact value check with literal
- **WHEN** evaluating `BoolExpr::Fact(FactQuery::Value { key: ":env", pattern: Literal("prod") })` against facts containing `:env` = `{"prod"}`
- **THEN** the predicate SHALL return true

#### Scenario: Fact value check with regex
- **WHEN** evaluating `BoolExpr::Fact` with a regex pattern against a fact set containing a matching member
- **THEN** the predicate SHALL return true

#### Scenario: Boolean combinators
- **WHEN** evaluating `BoolExpr::And` with two `Fact` sub-predicates where both match
- **THEN** the predicate SHALL return true

### Requirement: Polymorphic conditional branches
The system SHALL support conditional branches where each test can be a full `ArgMatcher`, an `Expr` (inline string predicate), or a `BoolExpr` (fact predicate). (CHANGED: syntax uses `fact?` instead of `has`)

#### Scenario: When with fact predicate
- **WHEN** using `(when (fact? [:env "prod"]) (effect :deny))` in args
- **THEN** the effect SHALL apply when the fact matches

#### Scenario: Unless with positional and fact
- **WHEN** using `(unless (and (fact? [:env "prod"]) (positional "delete")) (effect :allow))`
- **THEN** the effect SHALL apply when either predicate fails

#### Scenario: If with fact predicates
- **WHEN** using `(if (fact? [:env "prod"]) (effect :deny) (effect :allow))`
- **THEN** the appropriate branch SHALL apply based on fact evaluation

### Requirement: ContextFacts threading
The system SHALL thread `ContextFacts` through all argument evaluation functions. (CHANGED: uses set-based facts model; syntax uses `fact?` instead of `has`)

#### Scenario: Evaluate with context
- **WHEN** evaluating arguments with runtime facts in context
- **THEN** `fact?` predicates SHALL have access to those facts

#### Scenario: Facts from recursive evaluation
- **WHEN** `(may-i *)` adds `:via` facts during unwrapping
- **THEN** subsequent `fact?` predicates in the inner command SHALL see those facts

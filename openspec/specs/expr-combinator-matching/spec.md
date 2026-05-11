# expr-combinator-matching Specification

## Purpose

Contributor-only. Short-circuit semantics for `Expr::Or` in the evaluator: the first matching alternative wins, later alternatives are not evaluated, and only the first match's bound facts surface — so `(or [:a *] [:b *])` cannot leak both bindings into context.

## Requirements

### Requirement: Expr::Or matches if any sub-expression matches
`Expr::Or` SHALL return true if any sub-expression matches the value. The evaluation SHALL short-circuit on the first matching sub-expression. Only bound facts from the first matching sub-expression SHALL be included in the result. Later alternatives SHALL NOT be evaluated once a match is found.

#### Scenario: First sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"prod"`
- **THEN** it SHALL return matched=true

#### Scenario: Later sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"staging"`
- **THEN** it SHALL return matched=true

#### Scenario: No sub-expression matches
- **WHEN** matching `Expr::Or([Literal("prod"), Literal("staging")])` against `"dev"`
- **THEN** it SHALL return matched=false

#### Scenario: Bound facts from first matching branch only
- **WHEN** matching `Expr::Or([Bind(:a, Literal("prod")), Bind(:b, Literal("staging"))])` against `"staging"`
- **THEN** bound facts SHALL contain `:b = "staging"` but NOT `:a`

#### Scenario: Short-circuit prevents later binding leakage
- **WHEN** matching `Expr::Or([Bind(:x, Wildcard), Bind(:y, Wildcard)])` against `"val"`
- **THEN** bound facts SHALL contain only `:x = "val"`
- **AND** `:y` SHALL NOT be present in bound facts

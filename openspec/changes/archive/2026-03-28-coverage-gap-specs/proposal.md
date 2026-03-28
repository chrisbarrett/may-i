## Why

Tarpaulin coverage analysis reveals ~669 uncovered lines across production code. Many existing specs define _what_ types exist but not the full behavioral contract — particularly for arg pattern evaluation semantics, fact value query evaluation, expression combinator matching, define resolution through nested effects, and quantifier boundary conditions. Without specs, we can't write tests that attest to defined behaviour.

## What Changes

- Add specs for arg pattern evaluation semantics (effects and predicates) covering At position, Forbidden with wildcards, continuation fact threading, and boundary conditions not captured by existing specs
- Add specs for fact value query evaluation — how `FactQuery::Value` interacts with scalar/present/absent context values and complex `FactPattern` combinators
- Add specs for expression combinator matching (`Expr::And`/`Or`/`Not`) and how bound facts merge across combinators
- Add specs for define resolution through nested effect structures (If/Cond/And/Or/Not)
- Add specs for quantifier boundary semantics (Optional/OneOrMore/ZeroOrMore edge cases)

## Capabilities

### New Capabilities
- `arg-pattern-evaluation`: Behavioral contract for all ArgPattern variants (Positional, Exact, Anywhere, Forbidden, At) evaluated as both effects and predicates, including boundary conditions and wildcard semantics
- `fact-value-evaluation`: Behavioral contract for FactQuery::Value evaluation against scalar, present-only, and absent context values, plus FactPattern combinator evaluation (Regex, And, Or, Not)
- `expr-combinator-matching`: Behavioral contract for Expr::And/Or/Not matching with fact binding and merging semantics
- `define-resolution`: Behavioral contract for resolving named predicate references through nested effect structures (If, Cond, And, Or, Not)
- `quantifier-boundaries`: Behavioral contract for quantifier edge cases in positional pattern matching

### Modified Capabilities
- `partial-pattern-matching`: Add scenarios for At position pattern, Forbidden with wildcard, and Anywhere with wildcard — these ArgPattern variants lack behavioural scenarios

## Impact

- Spec files only — no code changes
- Specs in `openspec/specs/` provide the basis for writing property tests and targeted unit tests in phase 2

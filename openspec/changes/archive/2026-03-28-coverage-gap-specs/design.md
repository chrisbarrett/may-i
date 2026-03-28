## Context

Tarpaulin coverage analysis identified behavioural gaps where production code lacks corresponding specifications. The existing specs define types and basic happy paths but omit boundary conditions, error paths, and complex interaction semantics. This change adds specs only — no code changes.

## Goals / Non-Goals

**Goals:**
- Specify all uncovered evaluation behaviours so tests can attest to them
- Prioritise specs by coverage impact: engine eval > config parsing > supporting crates
- Each spec scenario maps directly to a testable assertion

**Non-Goals:**
- Writing the tests themselves (separate change)
- Specifying display/formatting code (pp, CST serialization) — low behavioural risk
- Specifying migration logic — already well-covered by migration_tests.rs

## Decisions

**Separate specs per concern rather than one monolithic spec**: Each capability gets its own spec file, matching the existing pattern in `openspec/specs/`. This keeps specs focused and reviewable.

**Modified partial-pattern-matching rather than new spec for At/Forbidden/Anywhere wildcards**: These are variants of the existing pattern matching spec, not new capabilities. Adding scenarios to the existing spec keeps related behaviour together.

**Spec fact value evaluation separately from fact predicates**: The existing `fact-predicates` spec covers type definitions and presence queries. Value query evaluation (scalar matching, pattern combinators on values) is a distinct behavioural concern warranting its own spec.

## Risks / Trade-offs

- [Spec drift] Specs may describe behaviour that differs from current implementation → Mitigated by deriving scenarios directly from reading the source code
- [Over-specification] Risk of specifying implementation details rather than behaviour → Mitigated by focusing on input/output contracts, not internal state

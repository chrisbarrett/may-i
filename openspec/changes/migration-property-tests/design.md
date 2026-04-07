## Context

The migration pipeline converts v1 config syntax to canonical syntax via 15 CST rewrite rules applied iteratively until convergence. The pipeline is: source text -> `parse_cst` -> `migrate_forms` (rewrite rules) -> `to_sexpr` -> `parse_config_from_sexprs` -> `Config` -> `evaluate`.

Existing test coverage: 353 unit tests (per-rule assertions), oracle snapshot tests (trace output against user's real config). No property-based tests verify the algebraic invariants.

Key infrastructure already exists:
- `crates/engine/src/test_generators.rs`: `any_eval_context_data()`, `any_predicate()`, `any_effect()`, `any_config()`
- `crates/core/src/test_generators.rs`: `any_keyword()`, `any_fact_query()`, `any_context_facts()`
- `crates/sexpr/src/cst.rs`: proptest strategies for s-expression strings, `Sexpr::PartialEq` ignores spans
- `may_i_engine::evaluate()`: pure function taking `(command, args, config, facts) -> EvalResult`

## Goals / Non-Goals

**Goals:**
- Verify the five migration properties (canonical fixed-point, idempotency, parseability, eval preservation, convergence) via proptest
- Catch semantic-breaking regressions in any of the 15 rewrite rules
- Generate readable minimal counterexamples via proptest shrinking

**Non-Goals:**
- Testing the evaluator itself (already covered by engine property tests)
- Testing the pretty-printer (layout is cosmetic, not semantic)
- Exhaustive v1 syntax coverage (wrapper variants, all arg pattern types) — start with the most common forms

## Decisions

### 1. String-based generators over AST-based generators

Generate config source text directly as strings rather than building `Config` ASTs and serializing them.

**Rationale:** `ToDoc` for `Effect` is incomplete — `And`, `Or`, `When`, `If`, `Cond`, `ArgPattern`, `CommandPattern` all render as placeholders. Writing a complete `Config -> canonical text` serializer would be significant work and a maintenance burden. String generators are simpler and directly test the parse path.

**Alternative considered:** Complete the `ToDoc`/`Display` impls. Rejected because it's orthogonal work and the string generators are sufficient for the testing goal.

### 2. Paired v1/canonical generators for eval preservation

Generate both the v1 form and the expected canonical form from the same random seed, rather than relying on a reference v1 evaluator (which doesn't exist).

**Rationale:** The system has no separate v1 evaluator — v1 configs are always transparently migrated before evaluation. By generating both forms together, we can parse each independently and compare evaluation results without needing a v1 eval path.

### 3. Test in the config crate with engine as dev-dependency

Place property tests in `crates/config/src/migrate/property_tests.rs` rather than in the engine crate or an integration test crate.

**Rationale:** Tests are colocated with the code they verify. The config crate already has the migration infrastructure; adding `may-i-engine` as a dev-dependency for eval comparison is lightweight.

### 4. Use `Sexpr` equality for canonical fixed-point

Compare `to_sexpr(migrate(parse_cst(s)))` with `parse(s)` using `Sexpr::PartialEq` (which ignores spans).

**Rationale:** String equality would be too strict (trivia/whitespace differences). `Sexpr` equality compares only structure, which is exactly what we want — the migration should not change the logical content of canonical configs.

## Risks / Trade-offs

- **Generator quality**: String generators might not cover all interesting syntactic forms. Mitigation: start with common patterns, extend as regressions are found.
- **Slow tests**: proptest with depth-recursive generators can be slow. Mitigation: limit depth to 2, case count to 256, and use `proptest_config` to bound shrinking.
- **Circular dependency**: Adding `may-i-engine` as a dev-dep of `may-i-config` creates a test-only cycle. Mitigation: dev-dependencies don't affect the build graph for non-test builds. If this causes issues, move eval-preservation tests to an integration test crate.

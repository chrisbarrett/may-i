## Why

A systematic codebase review identified 50+ findings across duplication, missing property tests, imprecise types, and code quality. One finding is a latent bug (nested-Or matching). Addressing these together reduces maintenance burden, prevents regressions, and makes the codebase more resistant to future bugs.

## What Changes

### Bug fix
- Delete `match_command_pattern` in engine and use `CommandPattern::is_match` — fixes silent failure on nested Or patterns

### Deduplication (~300 lines reduced)
- Replace `word_to_string` with `Word::to_str` in check.rs
- Unify `parse_command_args` and `parse_check_command` into shared helper
- Collapse Positional/Exact eval branches via shared helper with mode parameter
- Reuse `may_i_core::Span` instead of duplicate in config/migrate
- Implement `to_source()` via `to_doc()` for FactPattern/FactQuery
- Unify `CstNode::to_doc` and `to_doc_with_trivia` via shared generic helper
- Extract migration rewrite combinators (`tagged_list`, `rebuild_list`)
- Extract `check_refs_defined` in resolve.rs
- Extract render layout helpers (head, single-child, keyword-aware child)
- Add `parse_json` test helper and `TracingFold::from_config` constructor

### Type precision
- Move `vector_syntax` out of `FactQuery::Presence` into a rendering-layer wrapper
- Collapse `PositionalElementDetail` covarying Options into a `PositionalMatchKind` enum
- Change `BindDetail.key` from `String` to `Keyword`
- Unify `Allow/Ask/Deny` into `TerminalDecision { decision, reason }`
- Merge `Positional/Exact` ArgPattern variants into `Ordered { mode, patterns, continuation }`
- Move `source_text`/`pre_migration_forms` from `Config` to a `LoadedConfig` wrapper in the binary

### Property tests (19 new)
- Shell parser no-panic on arbitrary strings
- Config parser roundtrips (effect, predicate, command, rule)
- Migration semantic equivalence with defines
- `validate_and_resolve` no-panic
- Doc functor laws (identity, composition)
- Pretty-printer idempotency and width monotonicity
- Shell segment inverse
- Layout `write_layout` no-panic
- Transform idempotency (`truncate_matched_anywhere`, `dim_unevaluated`)
- ContextFacts merge commutativity
- Resolution completeness (no lingering Named predicates)
- Flag expansion subset property
- Lower-priority: rewrite convergence, FactQuery roundtrip, glob equivalences, Effect Display roundtrip, colorize content preservation, trace completeness

### Code quality
- Change `&String` → `&str` through the engine positional arg chain
- Fix `reason()` return type from `Option<&String>` to `Option<&str>`
- Remove redundant `#[must_use]` on Result-returning functions
- Simplify redundant closure in render_rule proptest
- Remove stale task comment in config.rs
- Tighten `pub` → `pub(crate)` on config/engine submodules and internal items
- Remove unused `_pattern` parameter in `extract_inner_command`
- Deduplicate decision-parsing logic in config.rs
- Clarify or merge `insert_scalar`/`push` on ContextFacts
- Replace unnecessary clones with `std::mem::take` where applicable

## Capabilities

### New Capabilities

- `deduplication`: Shared helpers and unified code paths replacing duplicated logic across crates
- `type-refinement`: Precise domain types replacing stringly-typed data and loose Option/bool usage
- `property-test-coverage`: New property-based tests covering parser safety, roundtrips, and algebraic laws
- `api-hygiene`: Tightened visibility, corrected parameter types, removed dead code

### Modified Capabilities

- `eval-fold-trait`: PositionalElementDetail, BindDetail, ArgMatchDetail types change shape
- `pattern-expressions`: Positional/Exact merge into Ordered; TerminalDecision replaces Allow/Ask/Deny
- `fact-predicates`: FactQuery::Presence loses vector_syntax field
- `transparent-config-migration`: Migration helpers extracted; Span type reused from core

## Impact

- **All crates** touched — core, engine, config, sexpr, pp, layout, binary
- **Breaking internal API**: fold detail types, ArgPattern variants, Effect terminal variants, FactQuery shape — all crate-internal, no external consumers
- **No CLI behaviour changes** — all changes are refactoring/correctness, except the nested-Or bug fix which makes matching more correct
- **Test suite**: ~19 new property tests added; existing tests updated for type changes

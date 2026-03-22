## Context

The may-i project currently has two s-expression parsers in `crates/sexpr/src/`:

1. **CST Parser** (`cst.rs`): Preserves all source formatting (whitespace, comments) using a fixpoint-of-functor pattern with `CstNode<A>`
2. **Sexpr Parser** (`sexpr.rs`): A simpler AST that discards trivia, producing `Sexpr` enum (Atom, List, Vector)

Both parsers tokenize the same way but build different representations. The v2/config module uses `Sexpr` exclusively via `may_i_sexpr::parse()`. The CST is used only for migration tooling via `may_i_sexpr::parse_cst()`.

The bug that triggered this change: CST serialization produces output that the Sexpr parser cannot parse due to differences in how they handle multi-line list formatting with indentation-based heuristics.

## Goals / Non-Goals

**Goals:**
- Consolidate to a single canonical parser (CST)
- Maintain backward compatibility for all existing code using `Sexpr`
- Fix the parser divergence bug
- Add generative tests for CST roundtrip correctness
- Reduce maintenance burden (delete ~700 lines of redundant code)

**Non-Goals:**
- Modifying v2/config module parsers (they continue using Sexpr)
- Changing Sexpr API or behavior
- Adding new features to either parser
- Converting v2/config to use CST directly

## Decisions

### Decision 1: CST as Canonical Parser
**Choice**: Use CST parser as the only parser, derive Sexpr as a view.
**Rationale**: CST is strictly more powerful (preserves trivia) and already exists. Converting CST → Sexpr is trivial (discard trivia). The reverse is impossible without losing information.

### Decision 2: Keep Sexpr as View Type
**Choice**: Retain `Sexpr` enum and its methods (`as_atom()`, `as_list()`, etc.) but remove its parser.
**Rationale**: Zero code churn in v2/config. The Sexpr type is a clean, simple interface that the config parsers expect. Keeping it as a view type derived from CST provides the best of both worlds.

### Decision 3: `parse()` Returns Sexpr
**Choice**: `may_i_sexpr::parse()` continues to return `Vec<Sexpr>` for backward compatibility.
**Rationale**: Implementation becomes: `parse_cst(input).map(|n| n.to_sexpr()).collect()`. Existing callers are unchanged.

### Decision 4: Sexpr Parser Implementation
**Choice**: Delete `sexpr.rs` parser code entirely; move `Sexpr` enum and methods to `lib.rs` or keep in `sexpr.rs` as type-only module.
**Rationale**: ~700 lines of redundant tokenization and parsing logic removed. Only the type definition and view methods remain.

## Risks / Trade-offs

| Risk | Mitigation |
|------|-----------|
| Performance regression from CST → Sexpr conversion | Benchmark before/after; conversion is O(n) and trivial (just field access and enum construction) |
| Breaking change if Sexpr behavior subtly differs | Comprehensive test suite validates behavior; generative tests catch edge cases |
| Loss of Sexpr-specific error messages | CST parser has equivalent or better error messages; verify with existing error tests |
| Migration complexity | Zero migration needed for callers; only internal crate changes |

## Migration Plan

This is an internal refactoring with no external migration required:

1. **Phase 1**: Implement `CstNode::to_sexpr()` method
2. **Phase 2**: Update `parse()` to use CST internally
3. **Phase 3**: Remove Sexpr parser code
4. **Phase 4**: Add generative tests
5. **Phase 5**: Verify all existing tests pass

Rollback: Revert commit if issues found (pure code change, no data migration).

## Open Questions

None - approach is straightforward and low-risk.

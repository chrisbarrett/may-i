## Why

The codebase currently maintains parallel v1 (legacy) and v2 (canonical) type hierarchies, causing confusion and technical debt. The v1 types in `types.rs` (3469 lines) have been replaced by v2 types in `ast.rs`, but dead code remains. Completing this migration will simplify the architecture, remove ~4000 lines of dead code, and establish a single source of truth for domain types.

## What Changes

- **BREAKING**: Delete `crates/core/src/types.rs` (v1 type definitions)
- **BREAKING**: Delete `crates/core/src/legacy/mod.rs` (legacy re-exports)
- **BREAKING**: Delete `crates/engine/src/visitors/` directory (v1 evaluator implementation, 9 files)
- **BREAKING**: Remove `evaluate_v1()` function from engine public API
- Migrate shared utility types to proper modules:
  - `Decision`, `ToDoc`, `Keyword` → `primitives.rs`
  - `Expr`, `ExprBranch`, `Quantifier` → `pattern.rs`
  - `FactPattern`, `FactQuery` → `predicates.rs`
  - `ContextFacts`, `ContextValue` → `context.rs`
  - `EvalResult` → `engine/src/lib.rs`
- Update all import statements across dependent crates
- Migrate 41 integration tests from v1 to v2 evaluator

## Capabilities

### New Capabilities
- `type-primitives`: Fundamental shared types (Decision, Keyword, ToDoc trait)
- `pattern-expressions`: Expression patterns for matching (Expr, Quantifier)
- `fact-predicates`: Fact-based predicate matching (FactPattern, FactQuery)
- `runtime-context`: Context facts for evaluation (ContextFacts, ContextValue)

### Modified Capabilities
- (none - this is internal refactoring with no behavioral changes)

## Impact

- **crates/core**: Complete restructuring - new modules, removal of types.rs and legacy/
- **crates/engine**: Removal of v1 evaluator, migration of EvalResult, test updates
- **crates/config**: Import updates in io.rs and migrate.rs
- **src/**: Import updates in cmd_claude_code_hook.rs
- **Breaking**: Any external code using v1 types or `may_i_engine::evaluate_v1` will break
- **Migration path**: Existing configs automatically converted via migrate.rs (already implemented)

## Why

The v2 syntax has been finalized and is now the canonical configuration format for may-i. However, the codebase still contains pervasive "v2" naming throughout modules, types, functions, and documentation. This naming is now vestigial—there is no "v1" alternative in active use. Removing these outdated references clarifies the codebase structure and signals that this is the standard, stable API.

## What Changes

**BREAKING**: This change restructures the public API by removing v2 prefixes and flattening module hierarchies:

- **Flatten v2 modules**: Move all files from `crates/*/src/v2/` into their parent `crates/*/src/` directories
- **Rename types**: Remove `V2` prefix from all public types (`V2Config` → `Config`, `V2Effect` → `Effect`, etc.)
- **Rename functions**: Remove `_v2` suffix from functions (`evaluate_v2` → `evaluate`, `load_v2` → `load`)
- **Update imports**: Change all `use crate::v2::` and `use may_i_core::v2::` to direct imports
- **Update comments**: Remove or update all comments referencing "v2 syntax" or "v2 unified DSL"
- **Archive legacy types**: Move legacy v1 types from `types.rs` to a `legacy` submodule to resolve naming conflicts
- **Update re-exports**: Simplify `crates/core/src/lib.rs` re-exports to remove aliased v2 types

## Capabilities

### New Capabilities
<!-- This is a refactoring change - no new capabilities introduced -->

### Modified Capabilities
<!-- No spec-level requirement changes - this is a structural rename -->

## Impact

- **Public API**: All `V2*` type aliases removed; types exported directly (e.g., `may_i_core::Config`)
- **Import paths**: `may_i_core::v2::ast::Config` → `may_i_core::Config`
- **Function names**: `may_i_engine::v2::evaluate_v2()` → `may_i_engine::evaluate()`
- **Module structure**: No more `v2/` subdirectories in `crates/core/src/`, `crates/config/src/`, `crates/engine/src/`
- **Documentation**: All user-facing docs updated to remove v2 references
- **Tests**: All test imports and assertions updated to use canonical names

Files affected across crates:
- `crates/core/src/lib.rs` - Re-export structure
- `crates/core/src/types.rs` - Legacy types moved to submodule
- `crates/core/src/v2/*` - Moved to parent directory
- `crates/config/src/v2/*` - Moved to parent directory
- `crates/config/src/io.rs` - Function renames
- `crates/engine/src/v2/*` - Moved to parent directory
- `src/cmd_*.rs` - Import updates
- `tests/**/*.rs` - Import and assertion updates

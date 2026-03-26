## Context

The may-i codebase currently maintains two type systems:

**Legacy v1 types** (`crates/core/src/types.rs`):
- `Config`, `Effect`, `Rule`, `Check`, `Wrapper`, `SecurityConfig`
- Used by: CLI commands (`cmd_check.rs`, `cmd_eval.rs`), engine visitors, config I/O

**Canonical v2 types** (`crates/core/src/v2/ast.rs`):
- Same names but different structures
- Re-exported from `lib.rs` with `V2` prefix: `V2Config`, `V2Effect`, `V2Rule`, etc.
- Used by: v2 parser, v2 evaluator, migration tooling

The current module structure:
```
crates/core/src/
├── lib.rs          # Re-exports both: types::* and v2::* as V2*
├── types.rs        # Legacy v1 types
└── v2/
    ├── mod.rs
    ├── ast.rs      # Canonical types (Config, Effect, Rule, etc.)
    └── pattern.rs  # Pattern types

crates/config/src/
└── v2/
    ├── mod.rs
    ├── config.rs   # Config parser
    ├── effect.rs   # Effect parser
    ├── rule.rs     # Rule parser
    ├── pattern.rs  # Pattern parser
    ├── predicate.rs
    ├── command.rs
    ├── resolve.rs  # Define resolution
    └── migrate.rs  # Migration tooling

crates/engine/src/
└── v2/
    ├── eval.rs     # evaluate_v2()
    └── trace.rs    # Effect tracing
```

Since v2 is now canonical, the "v2" naming throughout the codebase is confusing and signals instability. This design flattens the hierarchy and makes the canonical types the default.

## Goals / Non-Goals

**Goals:**
- Flatten all `v2/` subdirectories into their parent `src/` directories
- Remove `V2` prefix from all type names in public API
- Remove `_v2` suffix from all function names
- Update all imports across the codebase
- Resolve naming conflict between legacy and canonical types
- Update all documentation and comments

**Non-Goals:**
- Changing any behavior or semantics (pure renaming)
- Modifying the actual type definitions (only their names/paths)
- Deleting legacy types entirely (would require migrating all dependent code first)
- Updating external documentation outside the repo
- Adding new features or capabilities

## Decisions

### 1. Module Flattening Strategy

**Decision**: Move all `v2/` files directly into `src/`, not into a semantic subdirectory like `syntax/` or `dsl/`.

**Rationale**: 
- Simpler mental model: types live at the crate root level
- Consistent with how most Rust crates organize their primary types
- No semantic subdirectory needed since these ARE the canonical types

**Alternative considered**: Keep a semantic subdirectory (`syntax/` or `dsl/`)
- **Rejected**: Adds unnecessary nesting; the canonical types should be front-and-center

### 2. Legacy Type Resolution

**Decision**: Move legacy v1 types from `types.rs` to a `legacy` submodule (`may_i_core::legacy::Config`)

**Rationale**:
- Preserves backward compatibility for code still using legacy types
- Clear separation: `may_i_core::Config` (canonical) vs `may_i_core::legacy::Config` (deprecated)
- Allows gradual migration of dependent code

**Alternative considered**: Delete legacy types entirely
- **Rejected**: Would require refactoring ~6 files that still depend on legacy types (engine visitors, CLI commands)
- **Trade-off**: We keep deprecated code, but avoid a massive refactoring scope creep

**Alternative considered**: Rename legacy types with `Legacy` prefix in-place
- **Rejected**: Would require updating all call sites immediately, same scope problem

### 3. Re-export Structure

**Decision**: In `crates/core/src/lib.rs`:
```rust
// Canonical types (from flattened v2/ast.rs)
pub use ast::{Config, Effect, Rule, Define, Predicate, SecurityConfig, Spanned};
pub use pattern::{ArgPattern, CommandPattern, PositionalArg};

// Legacy types (moved to submodule)
pub mod legacy;
```

**Rationale**:
- Canonical types at crate root for convenience
- Legacy types accessible but clearly namespaced
- Follows Rust convention of keeping deprecated APIs in `legacy` or `deprecated` modules

### 4. Function Renaming

**Decision**: Rename with clear canonical names:
- `evaluate_v2()` → `evaluate()` (in `crates/engine/src/eval.rs`)
- `load_v2()` → `load()` (in `crates/config/src/io.rs`)

**Rationale**:
- These are the primary evaluation/loading functions
- No suffix needed since v2 is canonical
- Simple, clean API surface

### 5. File-by-File Migration Order

**Decision**: Process crates in dependency order:
1. `crates/core` - Foundation types (must be first, others depend on it)
2. `crates/config` - Config parsing (depends on core)
3. `crates/engine` - Evaluation (depends on core, config)
4. `src/` - CLI commands (depends on all above)
5. `tests/` - Test updates (last, depends on everything)

**Rationale**:
- Bottom-up ensures each crate's changes are valid before dependent crates update
- Prevents cascading compile errors that obscure root causes
- Each crate can be compiled and tested independently

## Risks / Trade-offs

**Risk**: Large-scale renaming could introduce subtle import errors or name resolution issues
- **Mitigation**: 
  - Compile after each crate's changes
  - Run full test suite before finalizing
  - Use compiler errors to guide fixes

**Risk**: Name collisions when both legacy and canonical types needed in same file
- **Mitigation**:
  - Use explicit paths: `legacy::Config` vs top-level `Config`
  - Gradually migrate files away from legacy types

**Risk**: External code using `may_i_core::V2Config` will break
- **Mitigation**:
  - This is an intentional BREAKING change per the proposal
  - Migration path is simple: `V2Config` → `Config`

**Risk**: Comment/docstring updates are manual and error-prone
- **Mitigation**:
  - Search for "v2" patterns after implementation
  - Review diff carefully for missed references

**Trade-off**: Keeping legacy types in `legacy` submodule maintains technical debt
- **Acceptance**: Necessary to avoid scope explosion; can be removed in future change

## Migration Plan

1. **Phase 1: Core crate** (1 task)
   - Move files from `v2/` to `src/`
   - Update `lib.rs` re-exports
   - Move `types.rs` content to `legacy/` submodule
   - Compile and fix errors

2. **Phase 2: Config crate** (1 task)
   - Move files from `v2/` to `src/`
   - Update imports to use canonical paths
   - Rename `load_v2()` → `load()`
   - Compile and fix errors

3. **Phase 3: Engine crate** (1 task)
   - Move files from `v2/` to `src/`
   - Update imports
   - Rename `evaluate_v2()` → `evaluate()`
   - Compile and fix errors

4. **Phase 4: CLI commands** (1 task)
   - Update imports in `src/cmd_*.rs`
   - Update function calls
   - Compile and fix errors

5. **Phase 5: Tests** (1 task)
   - Update all test imports and assertions
   - Run full test suite

6. **Phase 6: Documentation** (1 task)
   - Search and update all comments referencing "v2"
   - Update docstrings
   - Update README if needed

**Rollback strategy**: Since this is a rename-only change, rollback is a git revert. However, due to the breadth of changes, reverting may cause conflicts if new features are added on top. Best practice: complete this change quickly and avoid interleaving with other work.

## Open Questions

None - design is complete and ready for implementation.

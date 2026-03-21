## Context

The codebase currently maintains:
- **v1 code**: Archived in `archive/v1/` (engine, core, config modules) - dead code
- **v2 code**: Active in `crates/` with dual-path support via `lib.rs` and `lib_v1.rs`
- **Dual compatibility**: The engine supports both v1 and v2 evaluation paths
- **Test coverage gaps**: Significant untested code paths prevent reaching 90% coverage

Current structure:
```
archive/v1/
├── engine/          # ~200KB of legacy engine code
├── core/            # Legacy core types
└── config/          # Legacy config parsing

crates/engine/src/
├── lib.rs           # Current main (has both v1/v2 references)
├── lib_v1.rs        # Legacy v1 re-export
└── v2/              # Active v2 implementation
```

## Goals / Non-Goals

**Goals:**
1. Remove all v1 code from the codebase (archive and active code)
2. Consolidate v2 as the sole implementation
3. Achieve 90% line coverage across all workspace crates
4. Maintain all existing v2 functionality and public APIs
5. Preserve test compatibility (all existing tests must pass)

**Non-Goals:**
- Adding new features or capabilities beyond v2
- Changing v2 public APIs (except removing v1 compatibility)
- Performance optimization (may happen as side effect, but not a goal)
- Rewriting working v2 code

## Decisions

### 1. Archive Deletion Strategy
**Decision**: Delete entire `archive/v1/` directory without migration path.
**Rationale**: 
- Code has been archived for an extended period (git history preserves it)
- No active consumers of v1 API
- Migration complexity outweighs benefit
- **Alternative considered**: Gradual deprecation - rejected as unnecessary overhead

### 2. Engine Consolidation
**Decision**: Keep `lib.rs` as main entry point, remove `lib_v1.rs`.
**Rationale**:
- `lib.rs` already contains the working implementation
- `lib_v1.rs` appears to be a stale snapshot/re-export
- v2 module structure is already clean and organized
- **Alternative considered**: Rename `v2/` to root - rejected as unnecessary churn

### 3. Test Coverage Strategy
**Decision**: Add tests incrementally by module, prioritizing:
1. Core evaluation logic (`v2/eval.rs`)
2. Config parsing (`config/src/v2/`)
3. Public API surfaces
4. Edge cases and error paths
**Rationale**:
- Module-by-module approach allows incremental progress tracking
- Core evaluation is highest-value target
- Error paths typically uncovered and high-risk

### 4. Coverage Measurement
**Decision**: Use `cargo tarpaulin` (already installed) for coverage measurement.
**Rationale**:
- Already available in project environment
- No additional tooling needed
- Proven integration with project
- **Alternative considered**: `cargo-llvm-cov` - unnecessary since tarpaulin works

## Risks / Trade-offs

**Risk**: Accidentally delete active code paths mixed with v1 artifacts
→ **Mitigation**: Code review with explicit diff of deleted lines; verify `cargo test` passes after each deletion

**Risk**: Test coverage gaps in v2 code prevent reaching 90%
→ **Mitigation**: Identify coverage gaps early via `cargo tarpaulin --out Html`; create targeted tests for uncovered lines

**Risk**: Breaking changes to downstream consumers
→ **Mitigation**: This change explicitly breaks v1 API; consumers must migrate to v2 (already available)

**Risk**: Test flakiness from environment-dependent code (e.g., process env vars)
→ **Mitigation**: Use `#[serial]` for env-var tests; mock where possible

**Trade-off**: Deleting archive removes historical reference
→ **Acceptance**: Git history preserves it; no need to keep in working tree

## Migration Plan

### Phase 1: Archive Removal
1. Delete `archive/v1/` directory
2. Delete `crates/engine/src/lib_v1.rs`
3. Remove any v1 imports/references from active code
4. Verify `cargo build && cargo test` passes

### Phase 2: Coverage Baseline
1. Run baseline coverage: `cargo tarpaulin --workspace`
2. Identify coverage gaps per crate
3. Document target coverage per module

### Phase 3: Test Implementation
1. Add unit tests to `crates/engine/src/v2/eval.rs`
2. Add integration tests in `crates/engine/src/v2/integration_tests.rs`
3. Expand config tests in `crates/config/src/v2/`
4. Add shell-parser tests in `crates/shell-parser/src/tests.rs`
5. Add core tests in `crates/core/src/`

### Phase 4: Verification
1. Run full test suite: `cargo test --workspace`
2. Measure coverage: `cargo tarpaulin --workspace`
3. Verify ≥90% coverage on all crates
4. Review and remove any dead code revealed by coverage

### Rollback
Each phase is independently reversible via git revert. Archive deletion can be restored from git history if needed.

## Open Questions

1. Are there any v1 compatibility shims in `crates/engine/src/lib.rs` that need removal?
2. What's the current baseline coverage percentage?
3. Are there any test utilities in `archive/v1/` that should be preserved?
4. Should coverage gates be added to CI to prevent regression?

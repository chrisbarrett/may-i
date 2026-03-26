## Context

The codebase currently maintains two parallel type hierarchies:

**v1 (Legacy)** in `crates/core/src/types.rs` (3469 lines):
- Rule/effect model with `Config`, `Rule`, `Effect`, `RuleBody`
- Pattern matching with `ArgMatcher`, `PosExpr`, `CommandMatcher`
- Evaluation infrastructure: `EvalResult`, `TraceEntry`, `EvalAnn`
- Expression system: `Expr<E>`, `ExprBranch<E>`, `Quantifier`
- Context: `ContextFacts`, `ContextValue`
- Predicates: `FactPattern`, `FactQuery`

**v2 (Canonical)** in `crates/core/src/ast.rs` (839 lines):
- Unified effect model: `Effect`, `EffectResult`
- Unified predicate model: `Predicate`
- Simplified rule model: `Rule`, `Config`
- Same decision enum: `Decision`

The v1→v2 migration at the syntax level is complete via `crates/config/src/migrate.rs`, which transforms v1 s-expressions to v2 syntax at parse time. However, the v1 types still exist and are used by:
- The v1 evaluator (engine/src/visitors/, 9 files, ~4000 lines)
- Legacy module re-exports
- Import statements across 10+ files

## Goals / Non-Goals

**Goals:**
- Delete `types.rs` and `legacy/` module entirely
- Migrate remaining useful types to proper v2 modules
- Delete v1 evaluator (visitors/ directory)
- Migrate 41 integration tests to use v2 evaluator
- Update all import statements across the codebase
- Ensure no behavioral changes (pure refactoring)

**Non-Goals:**
- Changing migration logic (migrate.rs already works)
- Adding new features or changing behavior
- Modifying v2 evaluator logic (only test migration)
- Supporting v1 syntax indefinitely (v1 configs already auto-migrated)

## Decisions

### 1. Type Migration Destinations

| Source | Types | Destination | Rationale |
|--------|-------|-------------|-----------|
| `types.rs` | `Decision`, `ToDoc`, `Keyword` | `core/src/primitives.rs` | Fundamental types used everywhere |
| `types.rs` | `Expr`, `ExprBranch`, `Quantifier` | `core/src/pattern.rs` | Merge with existing pattern types |
| `types.rs` | `FactPattern`, `FactQuery` | `core/src/predicates.rs` | New module for fact matching |
| `types.rs` | `ContextFacts`, `ContextValue` | `core/src/context.rs` | Runtime evaluation context |
| `types.rs` | `EvalResult` | `engine/src/lib.rs` | Public API return type |

**Rationale**: Group related types by domain; minimize cross-module dependencies. `Decision` and `ToDoc` are truly shared primitives. `Expr` belongs with patterns. `EvalResult` is the evaluator's public interface.

### 2. Test Migration Strategy

The 41 tests currently use `evaluate_v1()` which parses shell commands and evaluates each segment. For v2 migration:

**Simple commands** (15 tests): Direct migration to v2 `evaluate()`:
```rust
// Before
let result = evaluate_v1("echo hello", &config);

// After  
let result = evaluate("echo", &["hello".to_string()], &config, &context);
```

**Compound commands** (26 tests): Create test helper that parses shell command and evaluates segments:
```rust
fn evaluate_compound(input: &str, config: &Config, context: &ContextFacts) -> EvalResult {
    let cmd = shell_parser::parse(input);
    evaluate_command_tree(&cmd, config, context) // recursive helper
}
```

**Rationale**: Preserves test coverage for complex shell constructs (pipelines, conditionals, loops) while using v2 evaluator for actual rule evaluation.

### 3. Module Structure

```
crates/core/src/
├── lib.rs              # Clean re-exports, no legacy
├── span.rs             # (unchanged)
├── doc.rs              # (unchanged)
├── ast.rs              # (unchanged - canonical types)
├── pattern.rs          # + Expr, ExprBranch, Quantifier
├── predicates.rs       # NEW: FactPattern, FactQuery
├── context.rs          # NEW: ContextFacts, ContextValue
└── primitives.rs       # NEW: Decision, ToDoc, Keyword

crates/engine/src/
├── lib.rs              # + EvalResult, - evaluate_v1
├── eval.rs             # (update imports only)
├── trace.rs            # (update imports only)
├── check.rs            # (update imports only)
├── matcher.rs          # (update imports only)
├── annotate.rs         # (update imports only)
└── [no visitors/ dir]
```

**Rationale**: Core types organized by domain. Engine focused on evaluation, not legacy support.

## Risks / Trade-offs

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Broken imports after type move | High | Medium | Comprehensive grep+update of all `use` statements; compile after each module |
| Test coverage gaps | Medium | Medium | Migrate tests incrementally; verify each passes before next |
| Public API breakage | High | High | Document breaking changes; users must update from `evaluate_v1` to `evaluate` |
| Accidental behavior change | Medium | High | Run full test suite after each phase; compare before/after outputs |
| Type inference issues with generics | Low | Medium | Explicit type annotations in migrated code; compile frequently |

**Trade-off**: We accept temporary complexity during migration (parallel type systems in flight) for long-term simplification (single type system, ~4000 fewer lines).

## Migration Plan

### Phase 1: Core Type Migration
1. Create `primitives.rs` with `Decision`, `ToDoc`, `Keyword`
2. Create `context.rs` with `ContextFacts`, `ContextValue`
3. Create `predicates.rs` with `FactPattern`, `FactQuery`
4. Add `Expr`, `ExprBranch`, `Quantifier` to `pattern.rs`
5. Update `core/src/lib.rs` re-exports
6. Compile and test core crate

### Phase 2: Engine Type Migration
1. Move `EvalResult` to `engine/src/lib.rs`
2. Update engine imports (`eval.rs`, `trace.rs`, `check.rs`, etc.)
3. Compile and test engine crate

### Phase 3: Delete Legacy Code
1. Delete `crates/core/src/types.rs`
2. Delete `crates/core/src/legacy/mod.rs`
3. Delete `crates/engine/src/visitors/` directory (all 9 files)
4. Remove `evaluate_v1` from `engine/src/lib.rs`
5. Compile - should fail on missing imports

### Phase 4: Update Imports
1. Update `crates/config/src/io.rs`
2. Update `src/cmd_claude_code_hook.rs`
3. Any other files with `legacy::` or `types::` imports
4. Compile and test full workspace

### Phase 5: Test Migration
1. Update test config helpers to return v2 `ast::Config`
2. Migrate 15 simple command tests
3. Create `evaluate_compound` helper
4. Migrate 26 compound command tests
5. Run full test suite

### Rollback
If issues arise:
1. Git revert to pre-migration state
2. The migration is self-contained in one commit
3. No database or external state changes

## Open Questions

None - all technical decisions resolved during planning conversation.

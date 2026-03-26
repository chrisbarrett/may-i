## Context

The v1 configuration format supported fact binding through wrapper definitions. A wrapper like `(wrapper "ssh" (positional [:ssh/host *] :command+args))` would capture the SSH host from positional arguments and inject it as a fact `:ssh/host` into the context. This enabled rules to check `(has [:ssh/host (regex "^prod-")])` to apply different policies based on the SSH host.

During the v1→v2 migration, this binding capability was lost. The migration code in `wrapper_to_rule()` explicitly strips the bracket notation:
```rust
// Convert v1 bracket capture patterns [:key *] to just * for v2
if let Some(vector) = pat.as_vector()
    && vector.len() == 2
    // ...
{
    // Replace [:key *] with just *
    pat = Box::new(CstNode::atom("*", pat.ann.clone()));
}
```

The v2 `Expr` type currently has no representation for binding. We need to add this capability back while maintaining v2's unified effect model.

## Goals / Non-Goals

**Goals:**
- Add `Keyword` type for validated keyword strings (must start with `:`)
- Add `Expr::Bind` variant to represent fact binding expressions
- Parse bracket notation `[:keyword]` and `[:keyword EXPR]` in positional patterns
- Evaluate bindings by capturing matched values and injecting them into context
- Update migration to preserve bindings instead of stripping them
- All 12 existing failing tests should pass

**Non-Goals:**
- Support for binding in non-positional contexts (e.g., `anywhere`, `forbidden`)
- Changing the `FactQuery` or `FactPattern` types to use `Keyword` (can be done later)
- New binding syntax beyond bracket notation
- Runtime binding validation (keywords are validated at parse time)

## Decisions

### 1. `Keyword` Type Design

**Decision**: Create a `Keyword` newtype wrapper around `String` that validates on construction.

**Rationale**:
- Correctness by construction - invalid keywords are impossible after construction
- Type safety distinguishes keywords from arbitrary strings
- Can be used consistently across `Expr::Bind`, `FactQuery`, and `FactPattern` in future

**Alternative considered**: Just use `String` with runtime validation. Rejected because we want to catch errors early and make invalid states unrepresentable.

### 2. `Expr::Bind` Structure

**Decision**: `Expr::Bind { key: Keyword, expr: Box<Expr> }`

**Rationale**:
- Compositional - wraps any existing expression
- Keyword is the fact key to bind to
- Inner expr is what to match against
- Mirrors v1's behavior: match a pattern AND capture the value

**Alternative considered**: `Expr::Bind { key: String, pattern: FactPattern }`. Rejected because we want to bind from expression matching (positionals use `Expr`), not just fact patterns.

### 3. Syntax: `[:keyword]` vs `[:keyword *]`

**Decision**: Both equivalent. `[:keyword]` alone means "bind anything" (wildcard). `[:keyword *]` is explicit but same meaning.

**Rationale**:
- Brackets provide visual distinction from regular expressions
- Optional `*` allows user to be explicit when desired
- Consistent with v1 behavior

### 4. Evaluation Strategy

**Decision**: Modify `match_expr` to return `(bool, ContextFacts)` instead of just `bool`.

**Rationale**:
- Bindings need to flow from pattern matching to context
- Positional matching happens in `match_positional_patterns` which calls `match_expr`
- When a Bind expression matches, the matched value is added to the returned facts
- Facts accumulate and flow to continuations

**Alternative considered**: Global context mutation. Rejected because it breaks referential transparency and makes testing harder.

### 5. Migration Strategy

**Decision**: Remove the stripping code and preserve bracket notation as `Expr::Bind`.

**Current migration**:
```rust
// Convert v1 bracket capture patterns [:key *] to just * for v2
if let Some(vector) = pat.as_vector() && ... {
    pat = Box::new(CstNode::atom("*", pat.ann.clone()));
}
```

**New migration**: Skip this transformation - let the v2 parser handle `[:key *]` directly as `Expr::Bind`.

## Risks / Trade-offs

**[Risk]** Changing `match_expr` return type affects many call sites
→ **Mitigation**: Create `match_expr_with_binding` as new function, keep `match_expr` as thin wrapper that discards facts for backward compatibility during migration

**[Risk]** Keyword validation might reject valid v1 configs that use unusual keys
→ **Mitigation**: Keyword validation only requires `:prefix`, allows any characters after. v1 keys already followed this pattern.

**[Risk]** Migration tests expect stripped output
→ **Mitigation**: Update test expectations in `test_wrapper_to_rule_with_capture_pattern` and `test_wrapper_to_rule_preserves_fact_binding`

**[Trade-off]** Adding `Expr::Bind` variant increases `Expr` size
→ **Acceptance**: Binding is a core feature, the overhead is justified

## Migration Plan

1. Implement `Keyword` type in `crates/core/src/types.rs`
2. Add `Expr::Bind` variant to `Expr` and `ExprF` enums
3. Update parser to recognize bracket syntax as `Expr::Bind`
4. Update evaluator to handle `Expr::Bind` in pattern matching
5. Remove migration code that strips bindings
6. Run all 12 failing tests - they should pass
7. Archive the change

Rollback: Revert to commit before this change. No database or persistent state changes.

## Open Questions

None - all design decisions resolved during discovery phase.


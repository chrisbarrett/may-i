## Context

The current may-i configuration language has two separate predicate domains:

1. **`ContextExpr`** (used in `(context ...)`) - supports `(has ...)` for fact queries
2. **`Expr`** (used in `(args ...)`) - only supports string predicates (literal, regex, wildcard, boolean ops)

This separation forces users to duplicate argument patterns across multiple rules when they need context-sensitive decisions. For example, allowing `kubectl delete` only when not in a production namespace requires either:
- Multiple nearly-identical rules with different `(context ...)` blocks
- Complex wrapper scripts that set facts based on arguments

The goal is to unify these domains by allowing fact predicates within argument matching.

## Goals / Non-Goals

**Goals:**
- Enable fact-based decisions within argument patterns
- Support mixing string predicates, list predicates, and fact predicates in conditional branches
- Preserve existing `Expr` conditionals for backward compatibility
- Maintain first-class `when`/`unless`/`if` forms (no desugaring) for trace fidelity
- Keep the mental model clear: `BoolExpr` for facts, `Expr` for strings, `ArgMatcher` for the mixing bowl

**Non-Goals:**
- Remove or deprecate existing `Expr` conditionals
- Allow `has` directly inside `Expr::And`/`Or` (must go through `ArgMatcher`)
- Support arbitrary nesting of fact predicates within string predicates (maintain type safety)
- Change how `(context ...)` works (it remains unchanged)

## Decisions

### 1. Create `BoolExpr` type for fact predicates
**Decision**: Add a new `BoolExpr` enum with `Has(FactQuery)`, `And(Vec<BoolExpr>)`, `Or(Vec<BoolExpr>)`, `Not(Box<BoolExpr>)`.

**Rationale**: Separating fact predicates from string predicates maintains type safety. Facts are `() -> bool`, strings are `String -> bool`. Mixing them arbitrarily creates confusing semantics.

**Alternative considered**: Add `Has` directly to `Expr`. Rejected because it would allow `(and "literal" (has ...))` which is semantically weird - the has doesn't consume the string argument.

### 2. Extend `ArgMatcher` with polymorphic conditionals
**Decision**: Add `ArgMatcher::Has(BoolExpr)` and make `ArgMatcher::Cond/When/Unless/If` branches accept `MatcherCondPredicate` which can be:
- `ArgMatcher` (full matcher)
- `Expr` (inline string check)
- `BoolExpr` (fact check)

**Rationale**: `ArgMatcher` is already the place where list-level decisions happen. It has access to both the argument list and the context facts. This is the natural mixing point.

**Example**:
```lisp
(args (when (and (has [:env "prod"])
                 (positional "delete"))
       (effect :deny)))
```

### 3. Thread `ContextFacts` through evaluation
**Decision**: Add `ContextFacts` parameter to `expr_matches_resolved`, `annotate_expr_arg`, and related functions.

**Rationale**: Fact predicates need access to the runtime context. Currently evaluation is pure string matching. We need to pass the facts through.

**Trade-off**: This adds a parameter to many functions, but it's explicit and clear.

### 4. Keep `Expr::{Cond,When,Unless,If}`
**Decision**: Preserve string-level conditionals in `Expr` for backward compatibility.

**Rationale**: The user's config uses `Expr::If` once (in tmux rule). Removing it would be a breaking change for minimal benefit. The distinction is:
- `Expr::Cond` - branches on string value
- `ArgMatcher::Cond` - branches on full argument pattern + facts

### 5. No desugaring of sugar forms
**Decision**: Keep `when`/`unless`/`if` as first-class AST nodes in `ArgMatcher`, not desugared to `cond`.

**Rationale**: Desugaring loses trace fidelity - users see `cond` in output but wrote `when`. First-class forms preserve intent.

## Risks / Trade-offs

**[Risk]** Parser ambiguity between `has` in `Expr` vs `BoolExpr` contexts
→ **Mitigation**: Context-sensitive parsing - `has` is only valid in `BoolExpr` contexts (ArgMatcher cond branches). If user writes `(and "literal" (has ...))`, parser will reject it.

**[Risk]** Complexity of polymorphic cond branches
→ **Mitigation**: Clear type distinction. Each branch predicate knows its own evaluation domain. Annotator handles each type appropriately.

**[Risk]** Breaking change for literal string "has" 
→ **Mitigation**: Unlikely to affect real configs. If user has `(positional "has")`, it still works - "has" is only special as a list head, not as a literal.

**[Risk]** EvalAnnotation explosion for new node types
→ **Mitigation**: Reuse existing annotation patterns. `BoolExpr::Has` annotates similarly to `ContextExpr::Has`.

## Migration Plan

No migration needed - this is a purely additive feature. Existing configs continue to work.

## Open Questions

1. **Evaluation order**: When evaluating `(and (has [:env "prod"]) (positional "delete"))`, should we evaluate the cheaper fact check first? Or preserve left-to-right?

2. **Effect propagation**: If a `BoolExpr::Has` appears in an `ArgMatcher::Or` and matches, should it be able to carry an effect? Current thinking: no, `has` is a boolean check only. Effects come from branches or explicit effect forms.

3. **Parser strategy**: Should we parse polymorphic branches eagerly (try each variant) or use lookahead? Eager parsing with backtracking might be simpler.

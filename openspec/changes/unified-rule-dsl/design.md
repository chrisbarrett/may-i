## Context

The current may-i policy DSL has evolved organically, resulting in several overlapping expression types:

- `ContextExpr` for facts in `(context ...)` forms (supports aliases via `defcontext`)
- `BoolExpr` for fact predicates in `(args ...)` forms (no aliases)
- `ArgMatcher` for argument matching with embedded effects (`cond`, `when`, `unless`, `if`)
- `Expr` for basic string patterns

This creates confusion about which combinators work where. For example, `(when ...)` in `args` can take a `BoolExpr`, `Expr`, or `ArgMatcher` via `MatcherCondPredicate`, but this polymorphism is ad-hoc and hard to extend.

Wrappers are currently a separate preprocessing phase that unwraps commands before rule evaluation. This makes wrapper behavior implicit and hard to trace.

## Goals / Non-Goals

**Goals:**
- Unify fact and argument queries into a single `Predicate` type
- Simplify rule syntax: `(rule COMMAND PREDICATE* EFFECT)`
- Replace wrappers with explicit recursive evaluation via `(may-i ...)` effect
- Enable named predicates via `(define NAME PREDICATE)`
- Provide clear semantics for effect combination
- Support automatic migration from v1 to v2 syntax
- Maintain trace output quality with dedicated AST nodes for sugar forms

**Non-Goals:**
- Backward compatibility (this is a breaking v2 redesign)
- User-defined functions (predicates are not functions, just named expressions)
- Let bindings for capturing args as facts (skip for now)
- Prelude/library system (skip for now)

## Decisions

### 1. Unified Predicate Type

**Decision**: Create a single `Predicate` enum that can query both facts and arguments.

```rust
pub enum Predicate {
    // Fact queries
    Has(FactQuery),
    
    // Argument queries
    Arg(ArgPattern),
    
    // Combinators
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
}
```

**Rationale**: Eliminates the need for `MatcherCondPredicate` and makes the DSL composable. Users can freely mix fact and argument checks: `(and (has :via/ssh) (positional "push"))`.

**Alternatives considered**:
- Keep separate types with explicit conversion: Rejected - still creates friction
- Type-level distinction: Rejected - overkill for this use case

### 2. Effects as First-Class with Recursion

**Decision**: Effects are separate from predicates and can include recursive evaluation.

```rust
pub enum Effect {
    Allow(Option<String>),
    Ask(Option<String>),
    Deny(Option<String>),
    Evaluate(ArgPattern),  // (may-i PATTERN)
    Case(Vec<(Predicate, Effect)>),  // Branching
    When(Predicate, Box<Effect>),    // Sugar - preserved for traces
    Unless(Predicate, Box<Effect>),  // Sugar - preserved for traces
    If(Predicate, Box<Effect>, Option<Box<Effect>>), // Sugar - preserved for traces
}
```

**Rationale**: Separating tests from effects clarifies semantics. Recursive evaluation is just another effect that can be combined with others.

**Alternatives considered**:
- Keep effects embedded in predicates (old model): Rejected - creates confusion about what returns what

### 3. Most Restrictive Effect Wins

**Decision**: When combining effects, Deny > Ask > Allow.

**Rationale**: Security-first approach. A deeply-nested deny should always be respected.

**Examples**:
- Outer `:allow` + Inner `:deny` → `:deny`
- Outer `:allow` + Inner `:ask` → `:ask`
- Outer `:ask` + Inner `:allow` → `:ask`

### 4. Simplified Rule Syntax

**Decision**: `(rule COMMAND PREDICATE* EFFECT)` where position 1 is always the command.

**Rationale**: Removes boilerplate `(command ...)` and `(args ...)` forms. Command matching is just the first positional match.

**Examples**:
```lisp
;; Old
(rule (command "git") (args (positional "push")) (effect :ask))

;; New
(rule "git" (positional "push") (effect :ask))

;; With command pattern
(rule (or "git" "gh") (effect :allow))
```

### 5. Dot Syntax for Remaining Args

**Decision**: Use `.` to indicate remaining args become the recursive evaluation target.

```lisp
(positional [:ssh/host *] . (may-i *))
```

**Rationale**: Explicit and follows Lisp cons-cell notation. Makes it clear which args are consumed vs passed to inner command.

**Alternatives considered**:
- Implicit: `(positional [:ssh/host *] (may-i *))` - Rejected, ambiguous about what (may-i *) applies to
- `&` or `...` syntax: Rejected, `.` is more idiomatic for "rest"

### 6. Recursion Depth Limit

**Decision**: Default limit of 10 recursive evaluations.

**Rationale**: Prevents infinite loops from malformed configs while allowing reasonable wrapper chains.

### 7. Parse vs Validate Phases

**Decision**: Separate parsing from validation.

1. Parse sexprs into AST
2. Resolve defines (runtime representation, not substitution)
3. Validate (cycle detection, etc.)

**Rationale**: Clear separation of concerns. Validation errors can reference source spans.

### 8. Sugar Form Preservation

**Decision**: `when`, `unless`, and `if` are dedicated AST nodes, not desugared.

**Rationale**: Trace output should reconstruct the original syntax. Desugaring then trying to reconstruct is error-prone.

## Risks / Trade-offs

**[Risk]** Breaking change requires all users to migrate configs
→ **Mitigation**: Auto-migration tool with clear error messages for edge cases

**[Risk]** Recursion cycles could cause stack overflow or infinite loops
→ **Mitigation**: Runtime depth limit with configurable default

**[Risk]** New syntax might be less readable for simple cases
→ **Mitigation**: Keep common cases concise, explicit for complex cases

**[Risk]** Trace output complexity increases with recursive evaluation
→ **Mitigation**: Clear indentation/nesting in trace output showing recursion levels

**[Trade-off]** Unified predicates lose some type safety
→ We gain composability and simpler mental model

**[Trade-off]** Effect combination rules are opinionated
→ Most-restrictive-wins is the secure default; users can override with explicit rules

## Migration Plan

1. **Phase 1**: Implement new parser and AST types alongside old (feature flag)
2. **Phase 2**: Implement new evaluator with recursive evaluation
3. **Phase 3**: Build migration tool with comprehensive tests
4. **Phase 4**: Update documentation and examples
5. **Phase 5**: Release v2.0 (breaking change)

**Rollback**: Users can pin to v1.x if needed. Migration tool produces backward-compatible output.

## Open Questions

None - all major design decisions resolved through exploration.

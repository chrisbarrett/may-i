## Context

The current v2 DSL (in `/crates/config/src/v2/`) implements a two-phase model:
1. **Predicates** test facts and arguments, returning Match/NoMatch
2. **Effects** produce decisions (Allow/Ask/Deny) for matching rules

This creates friction:
- Users think in terms of "what should I do" not "test then act"
- `and`/`or` have different meanings in predicates vs effects
- Complex rules require mental translation between phases

The unified model eliminates this split. Everything is an effect that returns:
- `Allow | Ask | Deny` → terminal decision, stop evaluating
- `Nil` → no match, continue to next effect

## Goals / Non-Goals

**Goals:**
- Unify predicates and effects into single Effect type returning decisions or Nil
- Enable composable effect chains where patterns can return Nil
- Support dot notation for "match this, then do that" patterns
- Provide clear `:effect` default mechanism
- Rename `has` to `fact?` for clarity
- Maintain ability to trace evaluation

**Non-Goals:**
- Backward compatibility with existing v2 (it's already breaking)
- Performance optimization beyond current v2
- New pattern types beyond what's in v1/v2
- Type safety for effect composition

## Decisions

### 1. Single Effect Type with Nil

**Decision**: Create unified `Effect` enum where all variants return `Decision | Nil`.

```rust
pub enum Effect {
    // Terminal decisions
    Allow(Option<String>),
    Ask(Option<String>),
    Deny(Option<String>),
    
    // Partial patterns (return Allow on match, Nil otherwise)
    CommandPattern(CommandPattern),  // "git", (or "git" "gh"), etc.
    ArgPattern(ArgPattern),          // (positional ...), (anywhere ...), etc.
    
    // Combinators
    And(Vec<Effect>),
    Or(Vec<Effect>),
    Not(Box<Effect>),
    
    // Conditionals
    When { predicate: Predicate, effect: Box<Effect> },
    Unless { predicate: Predicate, effect: Box<Effect> },
    If { predicate: Predicate, then_eff: Box<Effect>, else_eff: Box<Effect> },
    Cond { branches: Vec<(Predicate, Effect)>, fallback: Option<Box<Effect>> },
    
    // Recursion
    MayI { pattern: ArgPattern },  // returns inner decision or Nil
}
```

**Rationale**: Eliminates cognitive overhead of predicate vs effect distinction. Everything composes uniformly.

**Alternative**: Keep predicates separate - rejected, creates the friction we're solving.

### 2. Pattern Evaluation Returns Allow

**Decision**: Pattern matchers in effect position return `Allow` on success, `Nil` on failure.

```lisp
(rule "git"
  (positional "push")    ; returns Allow if matches, Nil otherwise
  :effect (effect :ask))
```

**Rationale**: Allows patterns to participate in effect chains naturally. `(and (positional "push") (effect :ask))` works as expected.

### 3. Dot Notation for Pattern-Effect Chains

**Decision**: Improper list syntax `(positional A B . EFFECT)` captures remaining args and passes to effect.

```lisp
(rule "ssh"
  (positional [:host *] . (may-i *))
  :effect (effect :allow))
```

**Rationale**: Clean syntax for wrappers. The dot visually separates "match this" from "then do that".

### 4. Command as First Effect

**Decision**: The first argument to `rule` is an effect that must return non-Nil for the rule to apply.

```lisp
(rule (or "git" "gh") ...)  ; "git" and "gh" are effects returning Allow on match
```

**Rationale**: Consistent with everything-is-an-effect model. Commands aren't special.

### 5. `:effect` Keyword for Default

**Decision**: Rules end with `:effect DEFAULT-EFFECT` keyword argument.

```lisp
(rule "git"
  (when (positional "push") (effect :ask))
  :effect (effect :allow))
```

**Rationale**: Explicit marker for the fallback. Without it, rules returning all Nil would be ambiguous.

### 6. Predicates Used in Conditionals

**Decision**: `when`/`unless`/`if`/`cond` still use predicates (Match/NoMatch) to decide which effect to evaluate.

```lisp
(when (and (has :via/ssh) (positional "push"))
  (effect :allow))
```

**Rationale**: We still need boolean logic for branching. Predicates remain but only appear in conditional contexts.

### 7. Rename `has` to `fact?`

**Decision**: Fact checking predicate renamed from `has` to `fact?`.

```lisp
(fact? [:via/ssh "prod-1"])  ; was (has [:via/ssh "prod-1"])
```

**Rationale**: Clearer that it's a predicate (question mark convention). Avoids confusion with "has" as possession.

### 8. Shorthand `:effect` Syntax

**Decision**: `:effect` accepts keyword shorthand `:allow/:ask/:deny` and vector shorthand `[:keyword "reason"]`.

```lisp
(rule "git" :effect :allow)                    ; same as :effect (effect :allow)
(rule "git" :effect [:ask "confirm"])          ; same as :effect (effect :ask "confirm")
(rule "git" :effect (when ... (effect :allow))) ; full form still works
```

**Rationale**: Reduces boilerplate for common cases. Most rules have simple terminal effects as defaults.

## Risks / Trade-offs

**[Risk]** Existing v2 code needs complete rewrite (AST, parser, evaluator)
→ **Mitigation**: v2 is not yet released publicly. This is the right time for breaking changes.

**[Risk]** Nil handling complexity in combinators
→ **Mitigation**: Simple semantics - `and` returns first Nil or last effect, `or` returns first non-Nil.

**[Risk]** Dot notation parsing complexity
→ **Mitigation**: CST supports improper lists naturally. Transform to `(match ... (then ...))` internal form.

**[Risk]** Confusion between predicates and effects in conditionals
→ **Mitigation**: Type system helps. Predicates only valid in `when`/`unless`/`if`/`cond` predicate position.

**[Trade-off]** Less type safety (effects can return Nil, predicates return Match/NoMatch)
→ **Acceptable**: Runtime validation catches errors. Simpler mental model worth the trade.

## Migration Plan

1. **Phase 1**: Redesign AST types in `may_i_core::v2::ast`
2. **Phase 2**: Rewrite parser in `may_i_config::v2`
3. **Phase 3**: Rewrite evaluator in `may_i_engine::v2::eval`
4. **Phase 4**: Update migration tool to target new syntax
5. **Phase 5**: Update tests and documentation

**Rollback**: Pin to commit before merge if issues arise.

## Open Questions

None - all major design decisions resolved.

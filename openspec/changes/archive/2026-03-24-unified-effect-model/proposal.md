## Why

The current v2 DSL separates predicates (Match/NoMatch) from effects (Allow/Ask/Deny), creating a two-phase evaluation model that doesn't match the user's mental model of partial pattern matching. The user wants a unified model where everything evaluates to a decision or "no match" (Nil), allowing composable effect chains with a default fallback.

This unification eliminates the distinction between "testing" and "acting" - everything is an effect that either produces a terminal decision or signals "keep looking" with Nil. This simplifies the mental model and enables more expressive rule composition.

## What Changes

**BREAKING**: Redesign the v2 rule syntax from `(rule COMMAND PREDICATE* EFFECT)` to `(rule COMMAND-EFFECT EFFECT* :effect DEFAULT)`.

- **New evaluation model**: All forms return `Allow | Ask | Deny | Nil` instead of the split predicate/effect model
- **Predicates become partial effects**: Pattern matchers like `(positional ...)`, `(anywhere ...)`, and command patterns return Allow on match, Nil otherwise
- **Effect combinators**: `(and ...)`, `(or ...)`, `(not ...)` work on effects, not predicates
- **Dot notation generalization**: Improper list syntax `(positional A B . EFFECT)` allows any effect after the dot, not just `(may-i *)`
- **Default effect**: New `:effect` keyword argument provides the fallback when all effects return Nil
- **Rename `has` to `fact?`**: Clearer semantics for fact checking in predicates
- **Simplified rule structure**: Everything between the rule name and `:effect` is an effect that can return Nil

## Capabilities

### New Capabilities

- `unified-effect-evaluation`: Effect system where all forms return decisions or Nil
- `partial-pattern-matching`: Pattern matchers that return Allow on match or Nil on failure
- `effect-combinators`: Boolean operations on effects (and/or/not) with Nil handling
- `improper-list-effects`: Dot notation for pattern-effect chains in positional matching

### Modified Capabilities

- `recursive-command-evaluation`: `(may-i PATTERN)` now returns Nil if pattern doesn't match
- `rule-definition-syntax`: Rule form changes to require `:effect` keyword for default

## Impact

- All existing v2 configs will need migration (but v1 migration path already planned)
- AST types in `may_i_core::v2::ast` require redesign
- Parser in `may_i_config::v2` needs complete rewrite
- Evaluator in `may_i_engine::v2::eval` needs new evaluation semantics
- Migration tool needs updates to target new syntax
- Documentation and examples need comprehensive updates

## Why

The current policy DSL has grown organically with separate, overlapping expression types for facts (`ContextExpr`, `BoolExpr`) and arguments (`ArgMatcher`, `Expr`). This creates confusion about which constructs work where, forces awkward polymorphic predicates (`MatcherCondPredicate`), and prevents meaningful abstraction. By unifying predicates into a single vocabulary that can query both facts and arguments, we simplify the mental model and enable powerful abstractions like named predicates.

Additionally, the current wrapper system requires a separate preprocessing phase. By treating wrapper unwrapping as recursive command evaluation within the rule system itself, we eliminate this complexity and make wrapper behavior explicit and traceable.

## What Changes

- **BREAKING**: New simplified rule syntax: `(rule COMMAND PREDICATE* EFFECT)` where position 1 is always the command
- **BREAKING**: Unified predicates - `(has ...)` queries facts, everything else queries arguments; both can be combined with `and`/`or`/`not`
- **BREAKING**: New `(define NAME PREDICATE)` form for reusable named predicates (replaces `defcontext`)
- **BREAKING**: `(may-i PATTERN)` becomes an effect that recursively evaluates inner commands (replaces wrapper preprocessing)
- **BREAKING**: Dot syntax for remaining args: `(positional [:host *] . (may-i *))`
- **BREAKING**: `when`/`unless`/`if` are now effects, not matchers
- **BREAKING**: `context` and `args` forms removed (functionality merged into unified predicates)
- **BREAKING**: Wrapper form removed (functionality replaced by rules with `(may-i ...)`)
- New effect combination rules: most restrictive wins (Deny > Ask > Allow)
- Recursion depth limit (default 10) for `(may-i ...)` evaluation
- Auto-migration tool to convert old syntax to new syntax
- New parser and evaluator implementations

## Capabilities

### New Capabilities
- `unified-predicate-dsl`: Single vocabulary for querying facts and arguments with boolean combinators
- `recursive-command-evaluation`: `(may-i PATTERN)` effect for recursive inner command evaluation
- `named-predicates`: `(define NAME PREDICATE)` for reusable predicate definitions
- `effect-combination`: Rules for combining multiple effects (explicit and recursive)
- `auto-migration`: Tool to automatically convert v1 syntax to v2 syntax

### Modified Capabilities
- None (this is a breaking redesign, not an incremental change)

## Impact

- **Parser** (`crates/config/src/parse/`): Complete rewrite of parsing logic
- **Core types** (`crates/core/src/`): New unified AST types
- **Engine** (`crates/engine/src/`): New evaluator with recursive evaluation support
- **CLI** (`crates/cli/src/`): New migration subcommand
- **Configuration files**: All existing `.lisp` configs need migration
- **Testing**: Existing tests will be replaced with new test suite

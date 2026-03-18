## Why

Currently, `(has ...)` queries for facts can only be used in `(context ...)` expressions. This limits the ability to make fine-grained authorization decisions that depend on both argument patterns AND runtime context. Users must create separate rules with duplicated argument patterns to handle different contexts, which is verbose and error-prone.

## What Changes

- **New `BoolExpr` type**: Dedicated fact predicate language supporting `has` and boolean combinators (`and`, `or`, `not`)
- **Extend `ArgMatcher`**: Add `Has(BoolExpr)` variant for fact checks within argument matching
- **Polymorphic conditionals**: Allow `ArgMatcher::Cond/When/Unless/If` branches to mix matchers, string predicates (`Expr`), and fact predicates (`BoolExpr`)
- **Thread `ContextFacts`**: Pass runtime context through all argument evaluation paths
- **First-class sugar forms**: Preserve `when`/`unless`/`if` in traces (no desugaring to `cond`)
- **Keep `Expr` conditionals**: Maintain backward compatibility for existing string-level conditionals in `Expr`

**BREAKING**: Parser will need to disambiguate `has` in expression contexts vs matcher contexts. Existing configs using `has` as a literal string in `Expr` positions may need quoting.

## Capabilities

### New Capabilities
- `fact-predicates-in-args`: Support for `(has ...)` and boolean fact combinators within `(args ...)` expressions, enabling correlated decisions based on both arguments and runtime facts

### Modified Capabilities
- None (existing `context` fact checking remains unchanged, `Expr` string conditionals remain backward compatible)

## Impact

- **Core types** (`crates/core/src/types.rs`): Add `BoolExpr` enum, extend `ArgMatcher` with `Has` and polymorphic conditionals
- **Parser** (`crates/config/src/parse/`): Update to parse `BoolExpr`, handle polymorphic cond branches, preserve sugar forms
- **Matcher** (`crates/engine/src/matcher.rs`): Thread `ContextFacts` through evaluation
- **Annotator** (`crates/engine/src/annotate.rs`): Handle new AST nodes, update annotations for mixed predicate types
- **Config validation**: May need updates for new syntax forms


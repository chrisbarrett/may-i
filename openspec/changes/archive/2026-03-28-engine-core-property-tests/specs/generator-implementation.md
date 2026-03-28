# Specification: Generator Implementation

## Overview

Technical specification for proptest generators supporting property-based testing.

## Generator Requirements

### Core Generators

#### `any_keyword()`
- **Output**: Valid `Keyword` values
- **Strategy**: Strings starting with `:`, alphanumeric + `-/_`
- **Examples**: `:foo`, `:bar-baz`, `:user/name`
- **Constraints**: Must start with `:`

#### `any_decision()`
- **Output**: `Decision` enum variants
- **Strategy**: Uniform distribution across `Allow`, `Ask`, `Deny`
- **Coverage**: All variants generated

#### `any_context_facts()`
- **Output**: `ContextFacts` with 0-10 entries
- **Strategy**: HashMap of keyword → context value
- **Value types**: Mix of `Present` and `Scalar` variants
- **Constraints**: No duplicate keys

#### `any_fact_pattern(depth: u32)`
- **Output**: Recursive `FactPattern` trees
- **Base case (depth=0)**: `Literal`, `Wildcard`, simple `Regex`
- **Recursive**: `And`, `Or`, `Not` combinations
- **Max depth**: 5
- **Max branch factor**: 4

#### `any_fact_query()`
- **Output**: `FactQuery` variants
- **Variants**: `Presence` and `Value`
- **Strategy**: Mix of both with random keys

#### `any_quantifier()`
- **Output**: `Quantifier` enum
- **Strategy**: Uniform across all variants
- **Variants**: `One`, `Optional`, `OneOrMore`, `ZeroOrMore`

#### `any_expr<E>(depth, effect_gen)`
- **Output**: Recursive `Expr<E>` trees
- **Generic**: Works with any effect type E
- **Base case**: `Literal`, `Regex`, `Wildcard`
- **Recursive**: `And`, `Or`, `Not`, `Cond`, `Bind`
- **Max depth**: 4

#### `any_positional_arg(depth)`
- **Output**: `PositionalArg` with quantifier and pattern
- **Components**: Quantifier + Expr + recursive flag
- **Strategy**: Random combination of components

#### `any_command_pattern(depth)`
- **Output**: `CommandPattern` trees
- **Base**: `Literal` command names
- **Recursive**: `Regex`, `Or` combinations
- **Max depth**: 4

#### `any_arg_pattern(depth)`
- **Output**: `ArgPattern` variants
- **Variants**: `Positional`, `Exact`, `Anywhere`, `Forbidden`, `At`
- **Max depth**: 4
- **Collection sizes**: 0-4 elements

### Engine Generators

#### `any_terminal_effect()`
- **Output**: `Effect::Allow`, `Ask`, `Deny`
- **Reasons**: Optional reason strings (50% have reasons)
- **Strategy**: All variants with/without reasons

#### `any_pattern_effect(depth)`
- **Output**: `Effect::CommandPattern`, `ArgPattern`
- **Components**: Command/arg patterns with various matchers

#### `any_effect(depth)`
- **Output**: Full recursive `Effect` trees
- **Base**: Terminal and pattern effects
- **Recursive**: `And`, `Or`, `Not`, `When`, `Unless`, `If`, `Cond`, `MayI`
- **Max depth**: 5
- **Collection sizes**: 1-5 elements (combinators)

#### `any_predicate(depth)`
- **Output**: Recursive `Predicate` trees
- **Base**: `Fact`, `Arg`, `Named`
- **Recursive**: `And`, `Or`, `Not`
- **Max depth**: 5

#### `any_eval_context()`
- **Output**: `EvalContext` with command, args, facts
- **Command**: Simple alphanumeric strings
- **Args**: 0-10 string arguments
- **Facts**: Random `ContextFacts`

#### `any_rule_set(size)`
- **Output**: Vector of `Rule` structs
- **Size**: 0-10 rules
- **Strategy**: Each rule has random command effect + effects

#### `any_config(size)`
- **Output**: Complete `Config` structure
- **Components**: defines, rules, security, checks
- **Size**: 0-10 rules, 0-5 defines

## Shrinking Behavior

### Automatic Shrinking (Proptest Default)
- Primitive types: Standard proptest shrinking
- Collections: Remove elements, shrink elements
- Enums: Try simpler variants

### Custom Shrinking (if needed)
- **Effects**: Replace combinators with first child
- **Predicates**: Simplify boolean expressions
- **Regex patterns**: Shrink to literal strings
- **ContextFacts**: Remove entries, simplify values

## Performance Constraints

### Generation Time
- Simple generators: <1ms per value
- Complex recursive (depth 5): <10ms per value
- Full config: <50ms per value

### Test Execution
- 256 cases × 30s timeout = ~2 hours worst case
- Typical: <5 seconds per property
- Target: All property tests complete in <60s total

## Edge Cases to Generate

### Strings
- Empty strings
- Single character
- Maximum length (100 chars)
- Special characters: spaces, quotes, newlines
- Unicode (if supported)

### Collections
- Empty
- Single element
- Maximum size

### Regex Patterns
- Simple literals
- Wildcards `.*`
- Character classes `[a-z]`
- Anchors `^$`
- Groups `(a|b)`

### Recursive Depth
- Minimal (0)
- Moderate (2-3)
- Maximum (5)

## Validation

Generated values must satisfy:
1. Type invariants (e.g., Keyword starts with `:`)
2. Regex patterns compile successfully
3. No infinite recursion in generation
4. Values are cloneable (for proptest)
5. Values implement `Debug` (for failure messages)

## Reproducibility

All generators must:
1. Use deterministic seeds in proptest
2. Produce same values given same seed
3. Support `PROPTEST_VERBOSE` for debugging
4. Support `PROPTEST_CASES` override

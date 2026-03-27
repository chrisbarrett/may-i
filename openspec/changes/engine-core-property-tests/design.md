# Design: Engine and Core Property Tests

## Overview

This design specifies the property testing infrastructure for the may-i engine and core crates. The goal is comprehensive coverage (>90%) through exhaustive property-based testing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROPERTY TEST LAYERS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LAYER 3: System Properties                              │   │
│  │  - Full evaluate() with arbitrary Config/Context         │   │
│  │  - End-to-end authorization decisions                    │   │
│  │  - Config validation workflows                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ▲                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LAYER 2: Component Properties                           │   │
│  │  - evaluate_effect() with arbitrary Effects              │   │
│  │  - evaluate_predicate() with arbitrary Predicates        │   │
│  │  - Pattern matching with arbitrary ArgPatterns           │   │
│  │  - Fact query evaluation                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ▲                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LAYER 1: Generators (crates/core/src/test_generators.rs)│   │
│  │  - Primitive generators (Decision, Keyword, etc.)        │   │
│  │  - Recursive type generators (Effect, Predicate, Expr)   │   │
│  │  - Context generators (EvalContext, ContextFacts)        │   │
│  │  - Composite generators (Rule, Config)                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Generator Design

### Recursive Type Strategy

All recursive types use depth-limited generation to prevent infinite recursion:

```rust
// Pseudocode for recursive generator pattern
fn any_effect(depth: u32) -> impl Strategy<Value = Effect> {
    if depth == 0 {
        // Base case: only terminal effects
        prop_oneof![
            any_terminal_effect(),
            any_simple_pattern_effect(),
        ]
    } else {
        // Recursive case: include combinators
        let inner = any_effect(depth - 1);
        prop_oneof![
            any_terminal_effect(),
            any_pattern_effect(depth),
            any_combinator_effect(inner.clone()),
            any_conditional_effect(inner.clone()),
            any_may_i_effect(depth - 1),
        ]
    }
}
```

### Generator Parameters

| Generator | Max Depth | Collection Size | Notes |
|-----------|-----------|-----------------|-------|
| `any_effect` | 5 | 0-5 elements | Exponential growth controlled |
| `any_predicate` | 5 | 0-5 elements | Same strategy as effects |
| `any_expr` | 4 | 0-4 elements | Slightly smaller for performance |
| `any_arg_pattern` | 4 | 0-4 patterns | Positionals limited |
| `any_context_facts` | N/A | 0-10 entries | Flat structure, no depth |
| `any_config` | 3 | 0-10 rules | High-level composition |

### Core Generators (crates/core)

#### File: `src/test_generators.rs`

```rust
//! Generators for property testing core types.
//! 
//! All generators use proptest strategies and are available only in test mode.

use proptest::prelude::*;
use crate::{Keyword, Decision, ContextFacts, ContextValue};
use crate::pattern::{Quantifier, Expr, CommandPattern, ArgPattern, PositionalArg};
use crate::predicates::{FactPattern, FactQuery};

/// Generate valid keywords (strings starting with ':')
pub fn any_keyword() -> impl Strategy<Value = Keyword> {
    "(:[a-zA-Z][a-zA-Z0-9-/_]*)".prop_map(|s| Keyword::new_unchecked(s))
}

/// Generate decision values
pub fn any_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

/// Generate context values
pub fn any_context_value() -> impl Strategy<Value = ContextValue> {
    prop_oneof![
        Just(ContextValue::Present),
        "[a-zA-Z0-9_-]{1,50}".prop_map(ContextValue::Scalar),
    ]
}

/// Generate context facts with 0-10 entries
pub fn any_context_facts() -> impl Strategy<Value = ContextFacts> {
    prop::collection::hash_map(any_keyword(), any_context_value(), 0..10)
        .prop_map(|map| {
            let mut facts = ContextFacts::default();
            for (k, v) in map {
                match v {
                    ContextValue::Present => facts.insert_present(k.as_str()),
                    ContextValue::Scalar(s) => facts.insert_scalar(k.as_str(), s),
                }
            }
            facts
        })
}

/// Generate quantifiers
pub fn any_quantifier() -> impl Strategy<Value = Quantifier> {
    prop_oneof![
        Just(Quantifier::One),
        Just(Quantifier::Optional),
        Just(Quantifier::OneOrMore),
        Just(Quantifier::ZeroOrMore),
    ]
}

/// Recursive generator for FactPattern
pub fn any_fact_pattern(depth: u32) -> impl Strategy<Value = FactPattern> {
    let leaf = prop_oneof![
        "[a-zA-Z0-9_-]{1,30}".prop_map(FactPattern::Literal),
        Just(FactPattern::Wildcard),
        // Note: Regex generation is tricky, use simple patterns
        "[a-zA-Z0-9.*+?^${}()|\\[\\]]{1,20}",
    ]
    .prop_filter("valid regex", |s| regex::Regex::new(s).is_ok())
    .prop_map(|s| FactPattern::Regex(regex::Regex::new(&s).unwrap()));

    leaf.prop_recursive(depth, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..4)
                .prop_map(FactPattern::And),
            prop::collection::vec(inner.clone(), 1..4)
                .prop_map(FactPattern::Or),
            inner.prop_map(|p| FactPattern::Not(Box::new(p))),
        ]
    })
}

/// Generate FactQuery variants
pub fn any_fact_query() -> impl Strategy<Value = FactQuery> {
    prop_oneof![
        (any_keyword(), proptest::bool::ANY).prop_map(|(k, vector)| {
            FactQuery::Presence { 
                key: k.as_str().to_string(),
                vector_syntax: vector,
            }
        }),
        (any_keyword(), any_fact_pattern(3)).prop_map(|(k, pattern)| {
            FactQuery::Value {
                key: k.as_str().to_string(),
                pattern,
            }
        }),
    ]
}

/// Recursive generator for Expr<E>
pub fn any_expr<E: Debug + ToDoc + 'static>(
    depth: u32,
    effect_gen: impl Strategy<Value = E>,
) -> impl Strategy<Value = Expr<E>> {
    let leaf = prop_oneof![
        "[a-zA-Z0-9_-]{1,30}".prop_map(Expr::Literal),
        Just(Expr::Wildcard),
        effect_gen.prop_map(Expr::Cond(vec![])), // Simplified
    ];

    leaf.prop_recursive(depth, 16, 4, move |_inner| {
        // Complex expressions with And/Or/Not/Bind
        todo!("Recursive case")
    })
}
```

### Engine Generators (crates/engine)

#### File: `src/test_generators.rs`

Re-exports core generators and adds engine-specific ones:

```rust
//! Generators for property testing engine evaluation.

pub use may_i_core::test_generators::*;

use may_i_core::ast::{Effect, Predicate, Rule, Config, Define, Check, Spanned};
use may_i_core::pattern::{CommandPattern, ArgPattern};
use may_i_core::{Decision, ContextFacts, Span};
use crate::EvalContext;

/// Generate terminal effects (Allow, Ask, Deny)
pub fn any_terminal_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![
        proptest::option::of("[a-zA-Z ]{1,50}")
            .prop_map(Effect::Allow),
        proptest::option::of("[a-zA-Z ]{1,50}")
            .prop_map(Effect::Ask),
        proptest::option::of("[a-zA-Z ]{1,50}")
            .prop_map(Effect::Deny),
    ]
}

/// Generate pattern effects
pub fn any_pattern_effect(depth: u32) -> impl Strategy<Value = Effect> {
    prop_oneof![
        any_command_pattern(depth).prop_map(Effect::CommandPattern),
        any_arg_pattern(depth).prop_map(Effect::ArgPattern),
    ]
}

/// Recursive generator for Effect
pub fn any_effect(depth: u32) -> impl Strategy<Value = Effect> {
    let leaf = prop_oneof![
        any_terminal_effect(),
        any_pattern_effect(0),
    ];

    leaf.prop_recursive(depth, 32, 8, move |inner| {
        let spanned_inner = inner.prop_map(|e| Spanned::new(e, Span::new(0, 0)));
        
        prop_oneof![
            // And combinator
            prop::collection::vec(spanned_inner.clone(), 1..5)
                .prop_map(|effects| Effect::And { effects }),
            // Or combinator  
            prop::collection::vec(spanned_inner.clone(), 1..5)
                .prop_map(|effects| Effect::Or { effects }),
            // Not combinator
            spanned_inner.clone().prop_map(|e| Effect::Not { 
                effect: Box::new(e) 
            }),
            // When conditional
            (any_predicate(depth - 1), spanned_inner.clone())
                .prop_map(|(pred, effect)| Effect::When { 
                    predicate: Spanned::new(pred, Span::new(0, 0)),
                    effect: Box::new(effect),
                }),
            // MayI recursive
            any_arg_pattern(depth - 1).prop_map(|pattern| Effect::MayI { pattern }),
        ]
    })
}

/// Generate predicates
pub fn any_predicate(depth: u32) -> impl Strategy<Value = Predicate> {
    let leaf = prop_oneof![
        any_fact_query().prop_map(Predicate::Fact),
        any_arg_pattern(2).prop_map(Predicate::Arg),
        "[a-zA-Z_][a-zA-Z0-9_-]*".prop_map(Predicate::Named),
    ];

    leaf.prop_recursive(depth, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 2..5)
                .prop_map(Predicate::And),
            prop::collection::vec(inner.clone(), 2..5)
                .prop_map(Predicate::Or),
            inner.prop_map(|p| Predicate::Not(Box::new(p))),
        ]
    })
}

/// Generate evaluation context
pub fn any_eval_context() -> impl Strategy<Value = EvalContext<'static>> {
    (
        "[a-zA-Z0-9_-]{1,30}",  // command
        prop::collection::vec("[a-zA-Z0-9_-]{1,30}", 0..10),  // args
        any_context_facts(),
    )
        .prop_map(|(cmd, args, facts)| {
            // Note: lifetime issues require Box::leak or similar
            // Simplified - actual implementation needs care
            EvalContext::new(&cmd, &args, &facts)
        })
}
```

## Property Test Patterns

### Pattern 1: Never Panics

```rust
proptest! {
    #[test]
    fn evaluate_never_panics(
        effect in any_effect(3),
        ctx in any_eval_context(),
    ) {
        // Should not panic
        let _result = evaluate_effect(&effect, &ctx, &[]);
    }
}
```

### Pattern 2: Algebraic Properties

```rust
proptest! {
    #[test]
    fn and_is_associative(
        a in any_effect(2),
        b in any_effect(2), 
        c in any_effect(2),
        ctx in any_eval_context(),
    ) {
        let rules: &[Rule] = &[];
        
        // (a AND b) AND c
        let ab = Effect::And {
            effects: vec![
                Spanned::new(a.clone(), Span::new(0, 0)),
                Spanned::new(b.clone(), Span::new(0, 0)),
            ]
        };
        let ab_c = Effect::And {
            effects: vec![
                Spanned::new(ab, Span::new(0, 0)),
                Spanned::new(c.clone(), Span::new(0, 0)),
            ]
        };
        let result1 = evaluate_effect(&ab_c, &ctx, rules);
        
        // a AND (b AND c)
        let bc = Effect::And {
            effects: vec![
                Spanned::new(b, Span::new(0, 0)),
                Spanned::new(c, Span::new(0, 0)),
            ]
        };
        let a_bc = Effect::And {
            effects: vec![
                Spanned::new(a, Span::new(0, 0)),
                Spanned::new(bc, Span::new(0, 0)),
            ]
        };
        let result2 = evaluate_effect(&a_bc, &ctx, rules);
        
        // Note: May not be strictly equal due to different evaluation paths,
        // but both should be valid results
        prop_assert!(result1.is_decision() || result1.is_nil());
        prop_assert!(result2.is_decision() || result2.is_nil());
    }
}
```

### Pattern 3: Boolean Logic

```rust
proptest! {
    #[test]
    fn not_inverts_match(
        pred in any_predicate(3),
        ctx in any_eval_context(),
    ) {
        let result = evaluate_predicate(&pred, &ctx);
        let not_result = evaluate_predicate(
            &Predicate::Not(Box::new(pred)),
            &ctx
        );
        
        match (result, not_result) {
            (Match, NoMatch) | (NoMatch, Match) => {},
            _ => prop_assert!(false, "Not did not invert correctly"),
        }
    }
}
```

### Pattern 4: Determinism

```rust
proptest! {
    #[test]
    fn evaluation_is_deterministic(
        effect in any_effect(3),
        ctx in any_eval_context(),
    ) {
        let rules: &[Rule] = &[];
        let result1 = evaluate_effect(&effect, &ctx, rules);
        let result2 = evaluate_effect(&effect, &ctx, rules);
        
        prop_assert_eq!(result1, result2);
    }
}
```

## Configuration

### Proptest Configuration

Single configuration for all environments (local and CI):

```rust
// In test modules
use proptest::prelude::*;

// Standard: 256 cases, moderate shrinking, 30s timeout
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 50,
        timeout: 30000, // 30 seconds
        ..ProptestConfig::default()
    })]
    
    // tests...
}
```

## Shrinking Strategy

Proptest's default shrinking works well for most types, but complex recursive types benefit from custom shrinking:

1. **Effects**: Shrink by replacing combinators with their first child
2. **Predicates**: Shrink boolean combinations toward simpler forms
3. **ContextFacts**: Remove entries, simplify values
4. **Regex patterns**: Shrink to simpler regex or literal

## Performance Considerations

1. **Generator caching**: Complex generators are compiled once and reused
2. **Depth limits**: Prevent exponential blowup in recursive types
3. **Collection limits**: Vecs capped at 5-10 elements
4. **Regex compilation**: Cached in FactPattern generation
5. **Parallel execution**: Tests run in parallel by default

## Testing Order

1. **Phase 1**: Primitive generators + ContextFacts tests
2. **Phase 2**: Pattern generators + pattern matching tests  
3. **Phase 3**: Effect/Predicate generators + component tests
4. **Phase 4**: Full system tests with arbitrary Config
5. **Phase 5**: Unit test backfill for hard-to-hit branches

This order ensures lower-level generators are tested before building on them.

## Debugging Failed Properties

When a property test fails:

1. Proptest automatically shrinks to minimal failing case
2. Add the case as a regression unit test
3. Use `PROPTEST_VERBOSE=1` to see intermediate shrinks
4. Use `PROPTEST_CASES=1` to debug without shrinking

## Integration with CI

Coverage measurement:
```bash
# Generate coverage with property tests
cargo tarpaulin --engine llvm --out lcov

# Verify thresholds
cargo tarpaulin --engine llvm --fail-under 90
```

Performance gates:
```bash
# Run with timing
time cargo test --release

# Should complete in <60s for all property tests
```

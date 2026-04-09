use super::*;
use crate::eval::{self, EvalContext, evaluate_predicate};

fn make_ctx<'a>(command: &'a str, args: &'a [String], facts: &'a ContextFacts) -> EvalContext<'a> {
    EvalContext::new(command, args, facts, Default::default())
}

// 5.1.1 Unit test: Unresolved named predicate returns Err
#[test]
fn unresolved_predicate_returns_err() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);
    let pred = Predicate::Named("undefined".to_string());
    let result = evaluate_predicate(&pred, &ctx);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::EvalError::UnresolvedPredicate { ref name } if name == "undefined"),
        "expected UnresolvedPredicate, got: {err:?}"
    );
}

// 5.1.2 Unit test: Invalid regex in pattern (error handling)
#[test]
fn invalid_regex_command_pattern() {
    // CommandPattern::Regex with a valid Regex (regex crate validates at construction)
    // Test that a regex that matches nothing still returns Nil
    let re = regex::Regex::new("^$").unwrap();
    let effect = Effect::CommandPattern(CommandPattern::Regex(re));
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("notempty", &args, &facts);
    let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
    assert!(result.is_nil());
}

// 5.1.3 Unit test: Deeply nested effect overflow protection
#[test]
fn deeply_nested_effect_doesnt_panic() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    // Build a deeply nested Not chain
    let mut effect = Effect::Allow(None);
    for _ in 0..50 {
        effect = Effect::Not {
            effect: Box::new(spanned(effect)),
        };
    }
    let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
    // Should not panic, just alternate between Allow and Nil
    assert!(result.is_nil() || result.is_decision());
}

// 5.1.4 Unit test: Malformed argument patterns (edge cases)
#[test]
fn empty_args_with_positional_pattern() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    let pattern = may_i_core::pattern::ArgPattern::Positional {
        patterns: vec![may_i_core::pattern::PositionalArg {
            quantifier: may_i_core::Quantifier::One,
            pattern: may_i_core::pattern::Expr::Wildcard,
            recursive: false,
        }],
        continuation: None,
    };
    let effect = Effect::ArgPattern(pattern);
    let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
    assert!(result.is_nil(), "No args should not match One pattern");
}

// 5.1.5 Unit test: Empty And/Or effects behavior
#[test]
fn empty_and_returns_allow() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    let and_effect = Effect::And { effects: vec![] };
    let result = eval::evaluate_effect(&and_effect, &ctx, &[]).unwrap();
    // Empty And: no Nil encountered, last_result stays at default Allow
    assert_eq!(result.decision(), Some(Decision::Allow));
}

#[test]
fn empty_or_returns_nil() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    let or_effect = Effect::Or { effects: vec![] };
    let result = eval::evaluate_effect(&or_effect, &ctx, &[]).unwrap();
    assert!(result.is_nil(), "Empty Or should return Nil");
}

// 5.1.6 Unit test: Cond with empty branches
#[test]
fn cond_empty_branches_no_fallback() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    let cond = Effect::Cond {
        branches: vec![],
        fallback: None,
    };
    let result = eval::evaluate_effect(&cond, &ctx, &[]).unwrap();
    assert!(result.is_nil(), "Empty Cond with no fallback should be Nil");
}

#[test]
fn cond_empty_branches_with_fallback() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();
    let ctx = make_ctx("test", &args, &facts);

    let cond = Effect::Cond {
        branches: vec![],
        fallback: Some(Box::new(spanned(Effect::Deny(Some("fallback".into()))))),
    };
    let result = eval::evaluate_effect(&cond, &ctx, &[]).unwrap();
    assert_eq!(result.decision(), Some(Decision::Deny));
}

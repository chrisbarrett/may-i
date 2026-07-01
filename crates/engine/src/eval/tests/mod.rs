use super::effects::{evaluate_effect, evaluate_effect_fold};
use super::positional::{
    build_expr_match_detail, build_positional_element_details, match_expr_with_binding,
};
use super::predicates::{evaluate_predicate, match_fact_pattern};
use super::*;

use std::collections::HashMap;

use may_i_core::ast::{Effect, EffectResult, Predicate, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern, MatchMode};
use may_i_core::{ContextFacts, Decision, FactPattern, FactQuery, Keyword};

use crate::fold::{EvalFold, PureFold};

fn kw(s: &str) -> Keyword {
    Keyword::new(s).unwrap()
}

use super::positional::match_pos_lit;

fn dummy_context<'a>(
    command: &'a str,
    args: &'a [String],
    facts: &'a ContextFacts,
) -> EvalContext<'a> {
    EvalContext::new(command, args, facts, Default::default())
}

#[test]
fn evaluate_terminal_effects() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("test", &[], &facts);
    let rules: &[Rule] = &[];

    assert_eq!(
        evaluate_effect(
            &Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            },
            &ctx,
            rules
        )
        .unwrap(),
        EffectResult::Decision(Decision::Allow, None)
    );
    assert_eq!(
        evaluate_effect(
            &Effect::Terminal {
                decision: Decision::Ask,
                reason: None
            },
            &ctx,
            rules
        )
        .unwrap(),
        EffectResult::Decision(Decision::Ask, None)
    );
    assert_eq!(
        evaluate_effect(
            &Effect::Terminal {
                decision: Decision::Deny,
                reason: None
            },
            &ctx,
            rules
        )
        .unwrap(),
        EffectResult::Decision(Decision::Deny, None)
    );
}

#[test]
fn evaluate_command_pattern() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("git", &[], &facts);
    let rules: &[Rule] = &[];

    let pattern = CommandPattern::Literal("git".to_string());
    assert_eq!(
        evaluate_effect(&Effect::CommandPattern(pattern), &ctx, rules).unwrap(),
        EffectResult::Decision(Decision::Allow, None)
    );

    let pattern = CommandPattern::Literal("hg".to_string());
    assert_eq!(
        evaluate_effect(&Effect::CommandPattern(pattern), &ctx, rules).unwrap(),
        EffectResult::Nil
    );
}

#[test]
fn evaluate_and_combinator() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("test", &[], &facts);
    let rules: &[Rule] = &[];

    // All non-Nil returns last
    let effects = vec![
        may_i_core::ast::Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            may_i_core::span::Span::new(0, 1),
        ),
        may_i_core::ast::Spanned::new(
            Effect::Terminal {
                decision: Decision::Ask,
                reason: None,
            },
            may_i_core::span::Span::new(0, 1),
        ),
    ];
    assert_eq!(
        evaluate_effect(&Effect::And { effects }, &ctx, rules).unwrap(),
        EffectResult::Decision(Decision::Ask, None)
    );
}

#[test]
fn evaluate_or_combinator() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("test", &[], &facts);
    let rules: &[Rule] = &[];

    // Returns first non-Nil
    let effects = vec![
        may_i_core::ast::Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            may_i_core::span::Span::new(0, 1),
        ),
        may_i_core::ast::Spanned::new(
            Effect::Terminal {
                decision: Decision::Deny,
                reason: None,
            },
            may_i_core::span::Span::new(0, 1),
        ),
    ];
    assert_eq!(
        evaluate_effect(&Effect::Or { effects }, &ctx, rules).unwrap(),
        EffectResult::Decision(Decision::Allow, None)
    );
}

#[test]
fn evaluate_not_combinator() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("test", &[], &facts);
    let rules: &[Rule] = &[];

    // Not of Allow returns Nil
    let effect = may_i_core::ast::Spanned::new(
        Effect::Terminal {
            decision: Decision::Allow,
            reason: None,
        },
        may_i_core::span::Span::new(0, 1),
    );
    assert_eq!(
        evaluate_effect(
            &Effect::Not {
                effect: Box::new(effect)
            },
            &ctx,
            rules
        )
        .unwrap(),
        EffectResult::Nil
    );
}

#[test]
fn predicate_evaluation() {
    let facts = ContextFacts::default();
    let ctx = dummy_context("test", &[], &facts);

    let pred = Predicate::Fact(FactQuery::Presence {
        key: kw(":missing"),
    });
    assert_eq!(
        evaluate_predicate(&pred, &ctx).unwrap(),
        PredicateResult::NoMatch
    );

    let mut facts = ContextFacts::default();
    facts.insert_present(kw(":present"));
    let ctx = dummy_context("test", &[], &facts);

    let pred = Predicate::Fact(FactQuery::Presence {
        key: kw(":present"),
    });
    assert_eq!(
        evaluate_predicate(&pred, &ctx).unwrap(),
        PredicateResult::Match
    );
}

#[test]
fn context_depth_tracking() {
    let facts = ContextFacts::default();
    let ctx = EvalContext::new("test", &[], &facts, Default::default()).with_recursion_limit(5);
    assert_eq!(ctx.recursion_limit, 5);
    assert!(!ctx.is_depth_exceeded());

    let deep_ctx = EvalContext {
        command: ctx.command,
        args: ctx.args,
        arg_expansions: ctx.arg_expansions.clone(),
        unresolved: Default::default(),
        facts: ctx.facts,
        bindings: Default::default(),
        recursion_depth: 5, // Set to equal recursion_limit
        recursion_limit: ctx.recursion_limit,
        parser: ctx.parser.clone(),
        parser_bindings: Default::default(),
        config: ctx.config,
        env_scope: None,
        dialect: ctx.dialect,
    };
    assert!(deep_ctx.is_depth_exceeded());
}

// --- Tests for fact binding in expressions ---

#[test]
fn fact_binding_captures_matched_value() {
    // When matching a Bind expression, the matched value should be captured
    use may_i_core::ast::Effect;
    use may_i_core::{Expr, Keyword};

    let bind_expr: Expr<Effect> = Expr::Bind {
        key: Keyword::new(":ssh/host").unwrap(),
        expr: Box::new(Expr::Wildcard),
    };

    // Match against "prod-server-01"
    let matched_value = "prod-server-01";

    // The match should succeed and bind the fact
    let (matched, bound_facts) = match_expr_with_binding(&bind_expr, matched_value);
    assert!(matched);
    assert_eq!(
        bound_facts.get_scalar(&kw(":ssh/host")),
        Some(matched_value)
    );
}

#[test]
fn match_expr_with_binding_and_expr() {
    use may_i_core::{Expr, Keyword};

    // Test And expression with Bind - all must match
    let and_expr: Expr<Effect> = Expr::And(vec![
        Expr::Bind {
            key: Keyword::new(":host").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
        Expr::Literal("prod".to_string()),
    ]);

    let (matched, facts) = match_expr_with_binding(&and_expr, "prod");
    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":host")), Some("prod"));

    // Should not match if second part fails
    let (matched, facts) = match_expr_with_binding(&and_expr, "dev");
    assert!(!matched);
    // First part matched and bound the fact
    assert_eq!(facts.get_scalar(&kw(":host")), Some("dev"));
}

#[test]
fn match_expr_with_binding_or_expr() {
    use may_i_core::{Expr, Keyword};

    // Test Or expression with Bind
    let or_expr: Expr<Effect> = Expr::Or(vec![
        Expr::Bind {
            key: Keyword::new(":special").unwrap(),
            expr: Box::new(Expr::Literal("special".to_string())),
        },
        Expr::Wildcard,
    ]);

    // First branch matches and binds
    let (matched, facts) = match_expr_with_binding(&or_expr, "special");
    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":special")), Some("special"));

    // Second branch matches, no binding from first
    let (matched, facts) = match_expr_with_binding(&or_expr, "anything");
    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":special")), None);
}

#[test]
fn match_expr_with_binding_not_expr() {
    use may_i_core::{Expr, Keyword};

    // Test Not expression - should not bind from inner
    let not_expr: Expr<Effect> = Expr::Not(Box::new(Expr::Bind {
        key: Keyword::new(":excluded").unwrap(),
        expr: Box::new(Expr::Literal("exclude".to_string())),
    }));

    // Inner matches, so Not fails - no binding
    let (matched, facts) = match_expr_with_binding(&not_expr, "exclude");
    assert!(!matched);
    assert_eq!(facts.get_scalar(&kw(":excluded")), None);

    // Inner doesn't match, so Not succeeds - still no binding
    let (matched, facts) = match_expr_with_binding(&not_expr, "include");
    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":excluded")), None);
}

#[test]
fn match_expr_with_binding_nested_bind() {
    use may_i_core::{Expr, Keyword};

    // Test Bind wrapping another Bind
    let nested_bind: Expr<Effect> = Expr::Bind {
        key: Keyword::new(":outer").unwrap(),
        expr: Box::new(Expr::Bind {
            key: Keyword::new(":inner").unwrap(),
            expr: Box::new(Expr::Wildcard),
        }),
    };

    let (matched, facts) = match_expr_with_binding(&nested_bind, "value");
    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":outer")), Some("value"));
    assert_eq!(facts.get_scalar(&kw(":inner")), Some("value"));
}

#[test]
fn match_expr_with_binding_bind_no_match() {
    use may_i_core::{Expr, Keyword};

    // Bind with inner expr that doesn't match - should not bind
    let bind_expr: Expr<Effect> = Expr::Bind {
        key: Keyword::new(":env").unwrap(),
        expr: Box::new(Expr::Literal("prod".to_string())),
    };

    let (matched, facts) = match_expr_with_binding(&bind_expr, "dev");
    assert!(!matched);
    assert_eq!(facts.get_scalar(&kw(":env")), None);
}

#[test]
fn match_positional_patterns_with_binding() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test positional patterns with fact binding
    let patterns = vec![
        PosTerm::single(
            Quantifier::One,
            Expr::Bind {
                key: Keyword::new(":cmd").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
        ),
        PosTerm::single(
            Quantifier::One,
            Expr::Bind {
                key: Keyword::new(":subcmd").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
        ),
    ];

    let arg1 = "git".to_string();
    let arg2 = "push".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2];
    let (matched, _, facts) = match_pos_lit(&args, &patterns);

    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":cmd")), Some("git"));
    assert_eq!(facts.get_scalar(&kw(":subcmd")), Some("push"));
}

#[test]
fn match_positional_patterns_no_match_with_binding() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test that facts are still captured even when pattern fails later
    let patterns = vec![
        PosTerm::single(
            Quantifier::One,
            Expr::Bind {
                key: Keyword::new(":host").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
        ),
        PosTerm::single(Quantifier::One, Expr::Literal("required".to_string())),
    ];

    let arg1 = "server".to_string();
    let arg2 = "wrong".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2];
    let (matched, _, facts) = match_pos_lit(&args, &patterns);

    assert!(!matched);
    // First arg was still bound before the failure
    assert_eq!(facts.get_scalar(&kw(":host")), Some("server"));
}

#[test]
fn match_positional_patterns_optional_with_binding() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test optional pattern with binding - arg present and matches
    let patterns = vec![PosTerm::single(
        Quantifier::Optional,
        Expr::Bind {
            key: Keyword::new(":opt").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
    )];

    let arg1 = "value".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, _, facts) = match_pos_lit(&args, &patterns);

    assert!(matched);
    assert_eq!(facts.get_scalar(&kw(":opt")), Some("value"));
}

#[test]
fn match_positional_patterns_one_or_more_with_binding() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test OneOrMore pattern with binding
    let patterns = vec![PosTerm::single(
        Quantifier::OneOrMore,
        Expr::Bind {
            key: Keyword::new(":items").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
    )];

    let arg1 = "a".to_string();
    let arg2 = "b".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2];
    let (matched, _, facts) = match_pos_lit(&args, &patterns);

    assert!(matched);
    // OneOrMore accumulates all matched values into the set
    assert!(facts.contains(&kw(":items"), "a"));
    assert!(facts.contains(&kw(":items"), "b"));
}

#[test]
fn match_positional_patterns_zero_or_more_with_binding() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test ZeroOrMore pattern with binding - matches all remaining
    let patterns = vec![PosTerm::single(
        Quantifier::ZeroOrMore,
        Expr::Bind {
            key: Keyword::new(":rest").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
    )];

    let arg1 = "a".to_string();
    let arg2 = "b".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2];
    let (matched, _, facts) = match_pos_lit(&args, &patterns);

    assert!(matched);
    // ZeroOrMore accumulates all matched values into the set
    assert!(facts.contains(&kw(":rest"), "a"));
    assert!(facts.contains(&kw(":rest"), "b"));
}

#[test]
fn match_positional_patterns_not_enough_args() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Keyword, Quantifier};

    // Test pattern with more patterns than args
    let patterns = vec![
        PosTerm::single(
            Quantifier::One,
            Expr::Bind {
                key: Keyword::new(":first").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
        ),
        PosTerm::single(
            Quantifier::One,
            Expr::Bind {
                key: Keyword::new(":second").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
        ),
    ];

    let arg1 = "only".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, _, _) = match_pos_lit(&args, &patterns);

    assert!(!matched);
}

#[test]
fn match_positional_patterns_one_or_more_no_args() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // Test OneOrMore fails with no args
    let patterns = vec![PosTerm::single(Quantifier::OneOrMore, Expr::Wildcard)];

    let args: Vec<&str> = vec![];
    let (matched, _, _) = match_pos_lit(&args, &patterns);

    assert!(!matched);
}

#[test]
fn match_positional_optional_patterns_skip_to_required() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (? "a") (? "b") "c" with args ["c"] -> match, consumed=1
    let patterns = vec![
        PosTerm::single(Quantifier::Optional, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::Optional, Expr::Literal("b".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("c".to_string())),
    ];

    let arg1 = "c".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 1);
}

#[test]
fn match_positional_optional_then_required_both_present() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (? "a") "b" with args ["a", "b"] -> match, consumed=2
    let patterns = vec![
        PosTerm::single(Quantifier::Optional, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("b".to_string())),
    ];

    let arg1 = "a".to_string();
    let arg2 = "b".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2];
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 2);
}

#[test]
fn match_positional_optional_skipped_required_present() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (? "a") "b" with args ["b"] -> match, consumed=1
    let patterns = vec![
        PosTerm::single(Quantifier::Optional, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("b".to_string())),
    ];

    let arg1 = "b".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 1);
}

#[test]
fn match_positional_optional_present_required_missing() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (? "a") "b" with args ["a"] -> no match (required "b" missing)
    let patterns = vec![
        PosTerm::single(Quantifier::Optional, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("b".to_string())),
    ];

    let arg1 = "a".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, _, _) = match_pos_lit(&args, &patterns);
    assert!(!matched);
}

#[test]
fn match_positional_zero_or_more_then_required() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (* "a") "b" with args ["a", "a", "b"] -> match, consumed=3
    let patterns = vec![
        PosTerm::single(Quantifier::ZeroOrMore, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("b".to_string())),
    ];

    let arg1 = "a".to_string();
    let arg2 = "a".to_string();
    let arg3 = "b".to_string();
    let args: Vec<&str> = vec![&arg1, &arg2, &arg3];
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 3);
}

#[test]
fn match_positional_zero_or_more_skipped_then_required() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (* "a") "b" with args ["b"] -> match, consumed=1
    let patterns = vec![
        PosTerm::single(Quantifier::ZeroOrMore, Expr::Literal("a".to_string())),
        PosTerm::single(Quantifier::One, Expr::Literal("b".to_string())),
    ];

    let arg1 = "b".to_string();
    let args: Vec<&str> = vec![&arg1];
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 1);
}

#[test]
fn match_expr_with_binding_regex() {
    use may_i_core::pattern::Expr;

    // Test Regex matching
    let expr: Expr<Effect> = Expr::Regex(regex::Regex::new("^prod-").unwrap());
    let (matched, facts) = match_expr_with_binding(&expr, "prod-server-01");
    assert!(matched);
    // Regex doesn't bind facts
    assert!(!facts.has(&kw(":anything")));

    let (matched, _) = match_expr_with_binding(&expr, "dev-server");
    assert!(!matched);
}

#[test]
fn match_expr_with_binding_literal() {
    use may_i_core::pattern::Expr;

    // Test Literal matching
    let expr: Expr<Effect> = Expr::Literal("exact".to_string());
    let (matched, facts) = match_expr_with_binding(&expr, "exact");
    assert!(matched);
    // Literal doesn't bind facts
    assert!(!facts.has(&kw(":anything")));

    let (matched, _) = match_expr_with_binding(&expr, "different");
    assert!(!matched);
}

#[test]
fn match_expr_with_binding_empty_and() {
    use may_i_core::pattern::Expr;

    // Test empty And expression
    let expr: Expr<Effect> = Expr::And(vec![]);
    let (matched, _) = match_expr_with_binding(&expr, "anything");
    assert!(matched);
}

#[test]
fn match_expr_with_binding_empty_or() {
    use may_i_core::pattern::Expr;

    // Test empty Or expression
    let expr: Expr<Effect> = Expr::Or(vec![]);
    let (matched, _) = match_expr_with_binding(&expr, "anything");
    assert!(!matched);
}

#[test]
fn match_expr_with_binding_and_all_fail() {
    use may_i_core::pattern::Expr;

    // Test And where all fail
    let expr: Expr<Effect> = Expr::And(vec![
        Expr::Literal("a".to_string()),
        Expr::Literal("b".to_string()),
    ]);
    let (matched, _) = match_expr_with_binding(&expr, "a");
    assert!(!matched);
}

#[test]
fn match_expr_with_binding_or_all_fail() {
    use may_i_core::pattern::Expr;

    // Test Or where all fail
    let expr: Expr<Effect> = Expr::Or(vec![
        Expr::Literal("a".to_string()),
        Expr::Literal("b".to_string()),
    ]);
    let (matched, _) = match_expr_with_binding(&expr, "c");
    assert!(!matched);
}

// --- Named predicate binding environment tests ---

#[test]
fn named_predicate_matches_when_fact_present() {
    let mut facts = ContextFacts::default();
    facts.insert_present(kw(":safe"));

    let body = Predicate::fact_presence(":safe");
    let bindings = HashMap::from([("safe", &body)]);

    let ctx = EvalContext::new("test", &[], &facts, bindings);
    let pred = Predicate::Named("safe".to_string());
    let result = evaluate_predicate(&pred, &ctx).unwrap();
    assert_eq!(result, PredicateResult::Match);
}

#[test]
fn named_predicate_no_match_when_fact_absent() {
    let facts = ContextFacts::default();

    let body = Predicate::fact_presence(":safe");
    let bindings = HashMap::from([("safe", &body)]);

    let ctx = EvalContext::new("test", &[], &facts, bindings);
    let pred = Predicate::Named("safe".to_string());
    let result = evaluate_predicate(&pred, &ctx).unwrap();
    assert_eq!(result, PredicateResult::NoMatch);
}

#[test]
fn named_predicate_transitive_resolution() {
    let mut facts = ContextFacts::default();
    facts.insert_present(kw(":x"));

    let body_a = Predicate::fact_presence(":x");
    let body_b = Predicate::Named("a".to_string());
    let bindings = HashMap::from([("a", &body_a), ("b", &body_b)]);

    let ctx = EvalContext::new("test", &[], &facts, bindings);
    let pred = Predicate::Named("b".to_string());
    let result = evaluate_predicate(&pred, &ctx).unwrap();
    assert_eq!(result, PredicateResult::Match);
}

#[test]
fn named_predicate_missing_returns_unresolved_error() {
    let facts = ContextFacts::default();
    let ctx = EvalContext::new("test", &[], &facts, Default::default());
    let pred = Predicate::Named("missing".to_string());
    let result = evaluate_predicate(&pred, &ctx);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), crate::EvalError::UnresolvedPredicate { ref name } if name == "missing")
    );
}

mod array_arguments;
mod const_arguments;
mod const_command_names;
mod dialect;
mod embedded_word_positions;
mod expansion;
mod heredoc;
mod loop_unrolling;
mod properties;
mod redirects_env;
pub(crate) mod strategies;

pub(crate) use strategies::{arb_shell_chars, arb_with_heredoc, arb_with_single_quoted_region};

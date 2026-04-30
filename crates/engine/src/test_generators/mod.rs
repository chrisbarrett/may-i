//! Proptest generators for engine evaluation types.
//!
//! Re-exports core generators and adds engine-specific generators
//! for Effect, Predicate, EvalContext, Rule, and Config.

use proptest::prelude::*;

#[cfg(test)]
use may_i_core::Keyword;
#[cfg(test)]
use may_i_core::ast::Check;
use may_i_core::ast::{Config, Effect, Predicate, Rule, SecurityConfig, Spanned};
#[cfg(test)]
use may_i_core::pattern::CommandPattern;
#[cfg(test)]
use may_i_core::pattern::MatchMode;
use may_i_core::{ContextFacts, Decision, Span};

// Re-export core generators.
pub use may_i_core::test_generators::*;

/// Shell keywords that the parser treats as tokens rather than command names.
/// Generated command names must avoid these to prevent parse mismatches in
/// check tests (where the shell parser is invoked on the command string).
#[cfg(test)]
const SHELL_KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "in", "while", "until", "do", "done", "case",
    "esac", "function",
];

#[cfg(test)]
fn is_shell_keyword(s: &str) -> bool {
    SHELL_KEYWORDS.contains(&s)
}

/// Generate a command name that is not a shell keyword.
#[cfg(test)]
fn any_command_name() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9]{0,9}".prop_filter("not a shell keyword", |s| !is_shell_keyword(s))
}

fn dummy_span() -> Span {
    Span::new(0, 0)
}

fn spanned<T>(value: T) -> Spanned<T> {
    Spanned::new(value, dummy_span())
}

/// Generate terminal effects (Allow, Ask, Deny) with optional reasons.
pub fn any_terminal_effect() -> BoxedStrategy<Effect> {
    let reason = proptest::option::of("[a-zA-Z ]{1,30}");
    prop_oneof![
        reason.clone().prop_map(|r| Effect::Terminal {
            decision: Decision::Allow,
            reason: r
        }),
        reason.clone().prop_map(|r| Effect::Terminal {
            decision: Decision::Ask,
            reason: r
        }),
        reason.prop_map(|r| Effect::Terminal {
            decision: Decision::Deny,
            reason: r
        }),
    ]
    .boxed()
}

/// Generate pattern effects (CommandPattern, ArgPattern).
pub fn any_pattern_effect(depth: u32) -> BoxedStrategy<Effect> {
    prop_oneof![
        any_command_pattern(depth).prop_map(Effect::CommandPattern),
        any_arg_pattern(depth).prop_map(Effect::ArgPattern),
    ]
    .boxed()
}

/// Generate recursive Effect trees with depth limiting.
pub fn any_effect(depth: u32) -> BoxedStrategy<Effect> {
    let leaf = prop_oneof![any_terminal_effect(), any_pattern_effect(0),];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 32, 8, move |inner| {
            let spanned_inner = inner.clone().prop_map(spanned);

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
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, effect)| Effect::When {
                        predicate: spanned(pred),
                        effect: Box::new(effect),
                    }),
                // Unless conditional
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, effect)| Effect::Unless {
                        predicate: spanned(pred),
                        effect: Box::new(effect),
                    }),
                // If conditional
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone(),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, then_eff, else_eff)| Effect::If {
                        predicate: spanned(pred),
                        then_effect: Box::new(then_eff),
                        else_effect: Box::new(else_eff),
                    }),
                // MayI recursive
                any_arg_pattern(depth.saturating_sub(1))
                    .prop_map(|pattern| Effect::MayI { pattern }),
            ]
        })
        .boxed()
    }
}

/// Generate Predicate trees with depth limiting.
pub fn any_predicate(depth: u32) -> BoxedStrategy<Predicate> {
    let leaf = prop_oneof![
        any_fact_query().prop_map(Predicate::Fact),
        any_arg_pattern(1).prop_map(Predicate::Arg),
    ];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 2..5).prop_map(Predicate::And),
                prop::collection::vec(inner.clone(), 2..5).prop_map(Predicate::Or),
                inner.prop_map(|p| Predicate::Not(Box::new(p))),
            ]
        })
        .boxed()
    }
}

/// Generate owned evaluation context data (command, args, facts).
pub fn any_eval_context_data() -> impl Strategy<Value = (String, Vec<String>, ContextFacts)> {
    (
        "[a-zA-Z][a-zA-Z0-9_-]{0,19}",
        prop::collection::vec("[a-zA-Z0-9_/-]{1,20}", 0..10),
        any_context_facts(),
    )
}

/// Generate a vector of Rules.
pub fn any_rule_set(size: usize) -> BoxedStrategy<Vec<Rule>> {
    prop::collection::vec(
        (any_effect(2), any_effect(2)).prop_map(|(cmd_effect, effect)| Rule {
            command_effect: spanned(cmd_effect),
            effect: spanned(effect),
            checks: vec![],
            span: dummy_span(),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }),
        0..size,
    )
    .boxed()
}

/// Generate complete Config structures.
pub fn any_config(size: usize) -> BoxedStrategy<Config> {
    any_rule_set(size)
        .prop_map(|rules| Config {
            defines: vec![],
            rules,
            security: SecurityConfig::default(),
            checks: vec![],
            args_styles: vec![],
        })
        .boxed()
}

#[cfg(test)]
mod additional_properties;
#[cfg(test)]
mod check_tests;
#[cfg(test)]
mod edge_case_tests;
#[cfg(test)]
mod effect_eval_tests;
#[cfg(test)]
mod fold_properties;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod predicate_eval_tests;

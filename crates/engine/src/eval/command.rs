use may_i_core::ast::Config;
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser as parser;

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult, SegmentDecision};

use super::context::DEFAULT_RECURSION_LIMIT;
use super::decompose::{EvalUnit, decompose};
use super::entry::evaluate_with_fold;

/// Evaluate a command string against config and context.
///
/// Parses the input, walks the AST to extract all simple commands and embedded
/// substitutions, evaluates each, and returns the aggregate (most restrictive)
/// decision.
pub fn evaluate_command(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
) -> Result<EvalResult, EvalError> {
    let mut fold = PureFold;
    evaluate_command_with_fold(input, config, facts, &mut fold)
}

/// Evaluate a command string with a custom fold for tracing.
pub fn evaluate_command_with_fold<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    evaluate_command_inner(input, config, facts, fold, 0, DEFAULT_RECURSION_LIMIT, 0)
}

/// `outer_offset` is the byte offset of `input` within the outermost original
/// command being evaluated — added to every emitted `SegmentDecision` so
/// nested embedded recursions report ranges in outermost coordinates.
fn evaluate_command_inner<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    limit: usize,
    outer_offset: usize,
) -> Result<EvalResult, EvalError> {
    if depth >= limit {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!("recursion depth limit ({limit}) exceeded")),
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let parse_result = parser::parse(input);
    let diagnostics = parse_result.diagnostics.clone();
    let has_parse_errors = parse_result.has_errors();
    let units = decompose(&parse_result.command, input);

    if units.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason: Option<String> = None;
    let mut segment_decisions: Vec<SegmentDecision> = Vec::new();

    for unit in &units {
        let unit_span = unit.span();
        let result = match unit {
            EvalUnit::SimpleCommand { command, args, .. } => {
                evaluate_with_fold(command, args, config, facts, fold)?
            }
            EvalUnit::EmbeddedCommand { source, span } => {
                let embedded_result = evaluate_command_inner(
                    source,
                    config,
                    facts,
                    fold,
                    depth + 1,
                    limit,
                    outer_offset + span.0,
                )?;
                fold.embedded_command(source, embedded_result.decision);
                embedded_result
            }
            EvalUnit::DynamicCommand { reason, .. } => {
                let _out = fold.default_ask(reason);
                EvalResult::new(Decision::Ask, Some(reason.clone()))
            }
        };

        // SimpleCommand and DynamicCommand carry their own segment entries
        // (one per unit). EmbeddedCommand units are wrappers — they only
        // relay their child segments, otherwise the inner range would appear
        // twice (once as the embed unit, once as the child SimpleCommand).
        if !matches!(unit, EvalUnit::EmbeddedCommand { .. }) {
            segment_decisions.push(SegmentDecision {
                start: outer_offset + unit_span.0,
                end: outer_offset + unit_span.1,
                decision: result.decision,
            });
        }
        // Inner segments arrive in outermost coordinates already (offset
        // applied during recursion).
        segment_decisions.extend(result.segment_decisions);

        if result.decision >= aggregate_decision {
            aggregate_decision = result.decision;
            aggregate_reason = result.reason;
        }
    }

    // Error-severity parse diagnostics floor the decision at Ask. The same
    // floor applies per-segment so display can colour without re-running the
    // engine — a parse error means each segment's boundary is uncertain.
    if has_parse_errors {
        if aggregate_decision < Decision::Ask {
            aggregate_decision = Decision::Ask;
            aggregate_reason = Some("parse error: ambiguous command boundary".to_string());
        }
        for seg in &mut segment_decisions {
            if seg.decision < Decision::Ask {
                seg.decision = Decision::Ask;
            }
        }
    }

    let mut eval_result = EvalResult::new(aggregate_decision, aggregate_reason);
    eval_result.parse_diagnostics = diagnostics;
    eval_result.segment_decisions = segment_decisions;
    Ok(eval_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::ast::{Config, Effect, SecurityConfig, Spanned};
    use may_i_core::pattern::CommandPattern;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn config_with_rules(rules: Vec<may_i_core::ast::Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn allow_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn deny_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Deny,
                reason: Some(format!("{cmd} denied")),
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn empty_facts() -> ContextFacts {
        ContextFacts::default()
    }

    // -- Simple command --

    #[test]
    fn simple_allowed_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn simple_no_rule_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- Compound commands --

    #[test]
    fn compound_and_most_restrictive() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello && rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn compound_deny_wins() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo hello; rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn compound_all_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("cat")]);
        let result = evaluate_command("echo a && echo b | cat", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Embedded commands --

    #[test]
    fn embedded_command_denied() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm -rf /)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn embedded_command_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("date")]);
        let result = evaluate_command("echo $(date)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn nested_embedded_command() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(echo $(rm -rf /))", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Dynamic command names --

    #[test]
    fn dynamic_command_name_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("$EDITOR file.txt", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("dynamic"));
    }

    // -- Empty input --

    #[test]
    fn empty_string_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("empty"));
    }

    #[test]
    fn whitespace_only_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("   ", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- If/for/case --

    #[test]
    fn if_then_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result =
            evaluate_command("if true; then rm -rf /; fi", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn or_evaluates_both_sides() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_command("false || rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn case_arm_deny() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command(
            "case $x in a) rm -rf /;; b) echo hi;; esac",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Process substitution --

    #[test]
    fn process_substitution_both_allowed() {
        let config = config_with_rules(vec![allow_rule("diff"), allow_rule("ls")]);
        let result = evaluate_command("diff <(ls /a) <(ls /b)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Recursion depth limit --

    // -- Parse diagnostics --

    #[test]
    fn parse_error_floors_allowed_at_ask() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated double quote — Error severity
        let result = evaluate_command(r#"echo "hello; rm -rf /"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(!result.parse_diagnostics.is_empty());
    }

    #[test]
    fn parse_error_does_not_downgrade_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        // Unterminated quote + denied command — deny > ask
        let result = evaluate_command(r#"rm "unterminated"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn parse_warning_does_not_floor() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("true")]);
        // Missing fi — Warning severity
        let result = evaluate_command("if true; then echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.parse_diagnostics.is_empty());
    }

    #[test]
    fn well_formed_has_no_diagnostics() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert!(result.parse_diagnostics.is_empty());
    }

    #[test]
    fn recursion_depth_limit() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("rm")]);
        // Create deeply nested: $(echo $(echo $(echo ...$(rm /)...)))
        let mut input = "rm /".to_string();
        for _ in 0..15 {
            input = format!("echo $({input})");
        }
        let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
        // Should hit depth limit and return Ask
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("depth"));
    }

    // -- segment_decisions: spec scenarios --

    #[test]
    fn segment_decisions_single_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hi", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.segment_decisions.len(), 1);
        let s = &result.segment_decisions[0];
        assert_eq!((s.start, s.end, s.decision), (0, 7, Decision::Allow));
    }

    #[test]
    fn segment_decisions_compound_and() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo a && rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let entries: Vec<_> = result
            .segment_decisions
            .iter()
            .map(|s| (s.start, s.end, s.decision))
            .collect();
        assert_eq!(
            entries,
            vec![(0, 6, Decision::Allow), (10, 18, Decision::Ask)]
        );
    }

    #[test]
    fn segment_decisions_embedded_substitution_present() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        // Outer simple command echo at 0..10 (Allow on its own).
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|s| s.start == 0 && s.end == 10 && s.decision == Decision::Allow)
        );
        // Inner rm covers the substitution body 7..9.
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|s| s.start == 7 && s.end == 9 && s.decision == Decision::Deny)
        );
    }

    #[test]
    fn segment_decisions_dynamic_command_is_ask() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("$EDITOR file.txt", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.segment_decisions.len(), 1);
        let s = &result.segment_decisions[0];
        assert_eq!(s.decision, Decision::Ask);
        assert_eq!(s.start, 0);
        assert_eq!(s.end, 16);
    }

    #[test]
    fn segment_decisions_empty_input_is_empty() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("", &config, &empty_facts()).unwrap();
        assert!(result.segment_decisions.is_empty());
    }

    #[test]
    fn segment_decisions_whitespace_input_is_empty() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("   ", &config, &empty_facts()).unwrap();
        assert!(result.segment_decisions.is_empty());
    }

    #[test]
    fn segment_decisions_nested_embed_contained_in_parent() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(echo $(rm))", &config, &empty_facts()).unwrap();
        // Locate the deny entry — must be contained in some other entry.
        let deny = result
            .segment_decisions
            .iter()
            .find(|s| s.decision == Decision::Deny)
            .expect("deny entry");
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|other| !std::ptr::eq(*&other, deny)
                    && other.start <= deny.start
                    && other.end >= deny.end
                    && (other.start < deny.start || other.end > deny.end)),
            "deny entry {:?} should be contained in some larger entry. all: {:?}",
            deny,
            result.segment_decisions
        );
    }

    #[test]
    fn segment_decisions_parse_error_floors_segment() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated double quote — Error severity floors aggregate to Ask
        // and per-segment Allow → Ask, so display can colour without
        // re-running the engine.
        let result = evaluate_command(r#"echo "hello"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .segment_decisions
                .iter()
                .all(|s| s.decision >= Decision::Ask)
        );
    }

    // -- segment_decisions: property tests --

    use proptest::prelude::*;

    fn arb_input() -> impl Strategy<Value = String> {
        // Limit to a sane shell-ish alphabet so the parser hits real shapes
        // (compound commands, embeddings, quotes) without spending all its
        // time on unparseable noise.
        proptest::string::string_regex(r#"[a-z0-9 ;|&"'$()<>/\-]{0,30}"#).unwrap()
    }

    fn top_level(decisions: &[crate::SegmentDecision]) -> Vec<&crate::SegmentDecision> {
        decisions
            .iter()
            .filter(|s| {
                !decisions.iter().any(|other| {
                    !std::ptr::eq(*&other, *s)
                        && other.start <= s.start
                        && other.end >= s.end
                        && (other.start < s.start || other.end > s.end)
                })
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 64, .. ProptestConfig::default() })]

        #[test]
        fn prop_top_level_segments_disjoint(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            let mut top = top_level(&result.segment_decisions);
            top.sort_by_key(|s| s.start);
            for pair in top.windows(2) {
                prop_assert!(
                    pair[0].end <= pair[1].start,
                    "overlapping top-level segments: {:?} and {:?} for input {:?}",
                    pair[0], pair[1], input
                );
            }
        }

        #[test]
        fn prop_aggregate_matches_strictest_top_level(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            let top = top_level(&result.segment_decisions);
            if top.is_empty() {
                return Ok(());
            }
            let mut strictest = top[0].decision;
            // The aggregate is strictest over ALL units (top + nested), so
            // match the ALL-segments max here too. See engine semantics in
            // `evaluate_command_inner`.
            for s in &result.segment_decisions {
                if s.decision > strictest {
                    strictest = s.decision;
                }
            }
            prop_assert_eq!(strictest, result.decision);
        }
    }
}

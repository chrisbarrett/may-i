use super::*;
use crate::check::run_checks;

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn run_checks_never_panics(config in any_config(5)) {
        let _ = run_checks(&config);
    }

    #[test]
    fn check_allow_evaluates_correctly(
        cmd_name in any_command_name(),
    ) {
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::Terminal { decision: Decision::Allow, reason: Some("allowed".into()) }),
                checks: vec![],
                span: dummy_span(),
                provenance: may_i_core::ast::Provenance::PrimaryConfig,
            }],
            checks: vec![Check {
                command: cmd_name,
                expected: Decision::Allow,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        for r in &results {
            prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
        }
    }

    // 4.4.3 Test: Failing checks have passed=false
    #[test]
    fn failing_check_has_passed_false(
        cmd_name in any_command_name(),
    ) {
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::Terminal { decision: Decision::Deny, reason: Some("denied".into()) }),
                checks: vec![],
                span: dummy_span(),
                provenance: may_i_core::ast::Provenance::PrimaryConfig,
            }],
            checks: vec![Check {
                command: cmd_name,
                expected: Decision::Allow, // Expect Allow but get Deny
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        for r in &results {
            prop_assert!(!r.passed, "Check should fail: expected {:?}, got {:?}", r.expected, r.actual);
        }
    }

    // 4.4.5 Test: Check with expected=Ask evaluates correctly
    #[test]
    fn check_ask_evaluates_correctly(
        cmd_name in any_command_name(),
    ) {
        // No rules match -> default Ask
        let config = Config {
            rules: vec![],
            checks: vec![Check {
                command: cmd_name,
                expected: Decision::Ask,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        for r in &results {
            prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
        }
    }

    // 4.4.7 Property: Check result matches expected decision
    #[test]
    fn check_result_matches_expected(
        cmd_name in any_command_name(),
        decision in any_decision(),
    ) {
        let effect = match decision {
            Decision::Allow => Effect::Terminal { decision: Decision::Allow, reason: Some("test".into()) },
            Decision::Ask => Effect::Terminal { decision: Decision::Ask, reason: Some("test".into()) },
            Decision::Deny => Effect::Terminal { decision: Decision::Deny, reason: Some("test".into()) },
        };
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(effect),
                checks: vec![],
                span: dummy_span(),
                provenance: may_i_core::ast::Provenance::PrimaryConfig,
            }],
            checks: vec![Check {
                command: cmd_name,
                expected: decision,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        for r in &results {
            prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
            prop_assert_eq!(r.actual, decision);
        }
    }

    #[test]
    fn check_deny_evaluates_correctly(
        cmd_name in any_command_name(),
    ) {
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::Terminal { decision: Decision::Deny, reason: Some("denied".into()) }),
                checks: vec![],
                span: dummy_span(),
                provenance: may_i_core::ast::Provenance::PrimaryConfig,
            }],
            checks: vec![Check {
                command: cmd_name,
                expected: Decision::Deny,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        for r in &results {
            prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
        }
    }
}

use super::*;
use crate::eval::evaluate;

fn make_rule(command: &str, body: Effect) -> Rule {
    Rule {
        command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
            command.into(),
        ))),
        effect: spanned(body),
        checks: vec![],
        span: dummy_span(),
        provenance: may_i_core::ast::Provenance::PrimaryConfig,
    }
}

fn terminal(decision: Decision, reason: Option<&str>) -> Effect {
    Effect::Terminal {
        decision,
        reason: reason.map(String::from),
    }
}

// 5.2.1 Integration test: Complex nested conditionals
#[test]
fn complex_nested_conditionals() {
    let args: Vec<String> = vec!["src".into()];
    let mut facts = ContextFacts::default();
    facts.insert_scalar(Keyword::new(":env").unwrap(), "prod");

    // Rule: when env=prod, if arg is "src" -> allow, else deny
    let config = Config {
        rules: vec![Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "deploy".into(),
            ))),
            effect: spanned(Effect::When {
                predicate: spanned(Predicate::Fact(may_i_core::FactQuery::Value {
                    key: Keyword::new(":env").unwrap(),
                    pattern: may_i_core::FactPattern::Literal("prod".to_string()),
                })),
                effect: Box::new(spanned(Effect::If {
                    predicate: spanned(Predicate::Arg(may_i_core::pattern::ArgPattern::Anywhere(
                        vec![may_i_core::pattern::Expr::Literal("src".to_string())],
                    ))),
                    then_effect: Box::new(spanned(Effect::Terminal {
                        decision: Decision::Allow,
                        reason: Some("prod deploy allowed".into()),
                    })),
                    else_effect: Box::new(spanned(Effect::Terminal {
                        decision: Decision::Deny,
                        reason: Some("prod deploy denied".into()),
                    })),
                })),
            }),
            checks: vec![],
            span: dummy_span(),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }],
        ..Config::default()
    };

    let result = evaluate("deploy", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Without the fact
    let empty_facts = ContextFacts::default();
    let result2 = evaluate("deploy", &args, &config, &empty_facts).unwrap();
    assert_eq!(result2.decision, Decision::Ask); // When doesn't match -> Nil -> Ask
}

// 5.2.2 Integration test: Multiple fact bindings
#[test]
fn multiple_fact_bindings() {
    let args: Vec<String> = vec![];
    let mut facts = ContextFacts::default();
    facts.insert_scalar(Keyword::new(":role").unwrap(), "admin");
    facts.insert_present(Keyword::new(":verified").unwrap());

    let config = Config {
        rules: vec![Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "admin-cmd".into(),
            ))),
            effect: spanned(Effect::When {
                predicate: spanned(Predicate::And(vec![
                    Predicate::Fact(may_i_core::FactQuery::Value {
                        key: Keyword::new(":role").unwrap(),
                        pattern: may_i_core::FactPattern::Literal("admin".to_string()),
                    }),
                    Predicate::Fact(may_i_core::FactQuery::Presence {
                        key: Keyword::new(":verified").unwrap(),
                    }),
                ])),
                effect: Box::new(spanned(Effect::Terminal {
                    decision: Decision::Allow,
                    reason: Some("admin verified".into()),
                })),
            }),
            checks: vec![],
            span: dummy_span(),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }],
        ..Config::default()
    };

    let result = evaluate("admin-cmd", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Missing :verified
    let mut partial_facts = ContextFacts::default();
    partial_facts.insert_scalar(Keyword::new(":role").unwrap(), "admin");
    let result2 = evaluate("admin-cmd", &args, &config, &partial_facts).unwrap();
    assert_eq!(result2.decision, Decision::Ask);
}

// 5.2.4 Integration test: Combined And/Or/Not in single rule
#[test]
fn combined_and_or_not_in_rule() {
    let args: Vec<String> = vec![];
    let facts = ContextFacts::default();

    // Rule: cmd matches AND (Allow OR (NOT Deny))
    // This should resolve to Allow
    let config = Config {
        rules: vec![Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "test".into(),
            ))),
            effect: spanned(Effect::And {
                effects: vec![
                    spanned(Effect::Or {
                        effects: vec![
                            spanned(Effect::Terminal {
                                decision: Decision::Allow,
                                reason: Some("or-allow".into()),
                            }),
                            spanned(Effect::Not {
                                effect: Box::new(spanned(Effect::Terminal {
                                    decision: Decision::Deny,
                                    reason: Some("inner-deny".into()),
                                })),
                            }),
                        ],
                    }),
                    spanned(Effect::Terminal {
                        decision: Decision::Allow,
                        reason: Some("and-second".into()),
                    }),
                ],
            }),
            checks: vec![],
            span: dummy_span(),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }],
        ..Config::default()
    };

    let result = evaluate("test", &args, &config, &facts).unwrap();
    // Or returns first non-Nil = Allow("or-allow")
    // And returns last = Allow("and-second")
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason, Some("and-second".to_string()));
}

// ── Order independence (order-independent-rules change) ─────────────

#[test]
fn order_independence_allow_and_deny_coexist_deny_wins() {
    // Spec: All applicable rules run; strictest non-Nil decision wins.
    let allow_rule = make_rule("rm", terminal(Decision::Allow, None));
    let deny_rule = make_rule("rm", terminal(Decision::Deny, Some("dangerous")));

    let facts = ContextFacts::default();
    let args: Vec<String> = vec![];

    // Allow before deny.
    let config = Config {
        rules: vec![allow_rule.clone(), deny_rule.clone()],
        ..Config::default()
    };
    let result = evaluate("rm", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.reason, Some("dangerous".to_string()));

    // Deny before allow.
    let config = Config {
        rules: vec![deny_rule, allow_rule],
        ..Config::default()
    };
    let result = evaluate("rm", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.reason, Some("dangerous".to_string()));
}

#[test]
fn order_independence_tied_deny_reasons_sorted_joined() {
    // Spec: Distinct reasons SHALL be sorted lexically and joined with `"; "`.
    // Same input in either source order yields the same aggregate.
    let r_b = make_rule("rm", terminal(Decision::Deny, Some("B")));
    let r_a = make_rule("rm", terminal(Decision::Deny, Some("A")));

    let facts = ContextFacts::default();
    let args: Vec<String> = vec![];

    let config = Config {
        rules: vec![r_b.clone(), r_a.clone()],
        ..Config::default()
    };
    let result_ba = evaluate("rm", &args, &config, &facts).unwrap();

    let config = Config {
        rules: vec![r_a, r_b],
        ..Config::default()
    };
    let result_ab = evaluate("rm", &args, &config, &facts).unwrap();

    assert_eq!(result_ba.decision, Decision::Deny);
    assert_eq!(result_ab.decision, Decision::Deny);
    assert_eq!(result_ba.reason, Some("A; B".to_string()));
    assert_eq!(result_ab.reason, Some("A; B".to_string()));
}

#[test]
fn order_independence_identical_deny_reasons_deduplicated() {
    let r1 = make_rule("rm", terminal(Decision::Deny, Some("no rm")));
    let r2 = make_rule("rm", terminal(Decision::Deny, Some("no rm")));

    let config = Config {
        rules: vec![r1, r2],
        ..Config::default()
    };
    let facts = ContextFacts::default();
    let args: Vec<String> = vec![];
    let result = evaluate("rm", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.reason, Some("no rm".to_string()));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 64, max_shrink_iters: 32, .. Default::default() })]

    // Property: shuffling rules in a config produces the same decision
    // and the same aggregate reason. Order independence invariant.
    #[test]
    fn order_independence_shuffle_preserves_decision_and_reason(
        decisions in proptest::collection::vec(
            proptest::sample::select(vec![Decision::Allow, Decision::Ask, Decision::Deny]),
            1..6,
        ),
        reasons in proptest::collection::vec("[a-z]{1,3}", 1..6),
        perm_seed in 0u64..1_000,
    ) {
        let n = decisions.len().min(reasons.len());
        let rules: Vec<Rule> = (0..n)
            .map(|i| make_rule("x", terminal(decisions[i], Some(&reasons[i]))))
            .collect();

        let config_a = Config { rules: rules.clone(), ..Config::default() };
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let result_a = evaluate("x", &args, &config_a, &facts).unwrap();

        // Deterministic shuffle keyed on perm_seed.
        let mut shuffled: Vec<Rule> = rules.clone();
        let len = shuffled.len();
        for i in (1..len).rev() {
            let j = ((perm_seed.wrapping_mul(2862933555777941757).wrapping_add(i as u64 * 3037000493)) as usize) % (i + 1);
            shuffled.swap(i, j);
        }
        let config_b = Config { rules: shuffled, ..Config::default() };
        let result_b = evaluate("x", &args, &config_b, &facts).unwrap();

        proptest::prop_assert_eq!(result_a.decision, result_b.decision);
        proptest::prop_assert_eq!(result_a.reason, result_b.reason);
    }
}

// ── shape-typed-bindings: trust hash stability (task 8.3) ───────────

#[test]
fn rule_trust_hash_unaffected_by_parser_shape_annotation() {
    // Trust hashing is over rule closures, grouped by program. Opting a
    // parser's parameter into a shape form changes the parser
    // declaration but not the rule text — so a rule approved before the
    // upgrade continues to verify. See design D8.
    let unannotated = may_i_config::parse_config(
        "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" #opts) (rest #cmd))\n\
         (rule \"ssh\" (allow \"fixed\"))",
    )
    .unwrap();
    let with_set = may_i_config::parse_config(
        "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" (set #opts)) (rest #cmd))\n\
         (rule \"ssh\" (allow \"fixed\"))",
    )
    .unwrap();
    let h1: Vec<String> = crate::trust::compute_trust_views(&unannotated)
        .iter()
        .map(|v| v.hash.clone())
        .collect();
    let h2: Vec<String> = crate::trust::compute_trust_views(&with_set)
        .iter()
        .map(|v| v.hash.clone())
        .collect();
    assert_eq!(h1, h2, "rule hash must not depend on shape annotation");
}

// ── shape-typed-bindings: quantifier capture flows into the body ────

#[test]
fn every_capture_visible_in_body_fact() {
    let config = may_i_config::parse_config(
        "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" (set #opts)) (rest #cmd))\n\
         (rule \"ssh\" (when (every? #opts [:ssh/opt *]) \
            (when (fact? [:ssh/opt \"BatchMode=yes\"]) (allow \"captured\"))))",
    )
    .unwrap();
    let args: Vec<String> = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "host"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let facts = ContextFacts::default();
    let result = evaluate("ssh", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason.as_deref(), Some("captured"));
}

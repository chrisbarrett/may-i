use super::*;
use crate::eval::evaluate;

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
                    then_effect: Box::new(spanned(Effect::Allow(Some(
                        "prod deploy allowed".into(),
                    )))),
                    else_effect: Box::new(spanned(Effect::Deny(Some("prod deploy denied".into())))),
                })),
            }),
            checks: vec![],
            span: dummy_span(),
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
                        vector_syntax: false,
                    }),
                ])),
                effect: Box::new(spanned(Effect::Allow(Some("admin verified".into())))),
            }),
            checks: vec![],
            span: dummy_span(),
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

// 5.2.3 Integration test: Recursive MayI with context
#[test]
fn recursive_may_i_with_context() {
    let args: Vec<String> = vec!["inner-cmd".into(), "arg1".into()];
    let facts = ContextFacts::default();

    let config = Config {
        rules: vec![
            // Wrapper rule: matches "wrapper", recurses into inner command
            Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "wrapper".into(),
                ))),
                effect: spanned(Effect::MayI {
                    pattern: may_i_core::pattern::ArgPattern::Positional {
                        patterns: vec![],
                        continuation: None,
                    },
                }),
                checks: vec![],
                span: dummy_span(),
            },
            // Inner rule: matches "inner-cmd"
            Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "inner-cmd".into(),
                ))),
                effect: spanned(Effect::Allow(Some("inner allowed".into()))),
                checks: vec![],
                span: dummy_span(),
            },
        ],
        ..Config::default()
    };

    let result = evaluate("wrapper", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason, Some("inner allowed".to_string()));
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
                            spanned(Effect::Allow(Some("or-allow".into()))),
                            spanned(Effect::Not {
                                effect: Box::new(spanned(Effect::Deny(Some("inner-deny".into())))),
                            }),
                        ],
                    }),
                    spanned(Effect::Allow(Some("and-second".into()))),
                ],
            }),
            checks: vec![],
            span: dummy_span(),
        }],
        ..Config::default()
    };

    let result = evaluate("test", &args, &config, &facts).unwrap();
    // Or returns first non-Nil = Allow("or-allow")
    // And returns last = Allow("and-second")
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason, Some("and-second".to_string()));
}

#[cfg(test)]
mod tests {
    use may_i_sexpr::cst::{CstNode, ShapeF, TriviaAnn};
    use proptest::prelude::*;

    use crate::migrate::migrate_forms;

    // ── CST node constructors ─────────────────────────────────────────

    fn atom(s: &str) -> Box<CstNode> {
        Box::new(CstNode::atom(s, Default::default()))
    }

    fn str_node(s: &str) -> Box<CstNode> {
        Box::new(CstNode {
            ann: TriviaAnn::default(),
            shape: ShapeF::String(s.into()),
        })
    }

    fn list(children: Vec<Box<CstNode>>) -> Box<CstNode> {
        Box::new(CstNode::list(children, Default::default()))
    }

    // ── Canonical CST generators ──────────────────────────────────────

    fn any_command_cst() -> BoxedStrategy<Box<CstNode>> {
        prop_oneof![
            "[a-z][a-z0-9_-]{0,10}".prop_map(|s| str_node(&s)),
            prop::collection::vec(
                "[a-z][a-z0-9_-]{0,10}".prop_map(|s| str_node(&s)),
                2..=4
            )
            .prop_map(|cmds| {
                let mut children = vec![atom("or")];
                children.extend(cmds);
                list(children)
            }),
            "[a-z][a-z.*+?]{0,10}"
                .prop_map(|s| list(vec![atom("regex"), str_node(&s)])),
        ]
        .boxed()
    }

    fn any_terminal_effect_cst() -> BoxedStrategy<Box<CstNode>> {
        prop_oneof![
            Just(list(vec![atom("effect"), atom(":allow")])),
            Just(list(vec![atom("effect"), atom(":deny")])),
            Just(list(vec![atom("effect"), atom(":ask")])),
            "[a-z ]{1,20}".prop_map(|r| list(vec![
                atom("effect"),
                atom(":allow"),
                str_node(r.trim())
            ])),
            "[a-z ]{1,20}".prop_map(|r| list(vec![
                atom("effect"),
                atom(":ask"),
                str_node(r.trim())
            ])),
            "[a-z ]{1,20}".prop_map(|r| list(vec![
                atom("effect"),
                atom(":deny"),
                str_node(r.trim())
            ])),
        ]
        .boxed()
    }

    fn any_keyword_cst() -> BoxedStrategy<Box<CstNode>> {
        prop_oneof![
            Just(atom(":via/ssh")),
            Just(atom(":in/ci")),
            Just(atom(":tool/docker")),
            "[a-z]{1,8}".prop_map(|s| atom(&format!(":{}", s))),
        ]
        .boxed()
    }

    fn any_predicate_cst(depth: u32) -> BoxedStrategy<Box<CstNode>> {
        if depth == 0 {
            any_keyword_cst()
                .prop_map(|k| list(vec![atom("fact?"), k]))
                .boxed()
        } else {
            prop_oneof![
                any_predicate_cst(0),
                (any_predicate_cst(depth - 1), any_predicate_cst(depth - 1))
                    .prop_map(|(a, b)| list(vec![atom("and"), a, b])),
                (any_predicate_cst(depth - 1), any_predicate_cst(depth - 1))
                    .prop_map(|(a, b)| list(vec![atom("or"), a, b])),
                any_predicate_cst(depth - 1).prop_map(|p| list(vec![atom("not"), p])),
            ]
            .boxed()
        }
    }

    /// Generate canonical effects that are true fixed points of migration.
    ///
    /// Constraints to avoid triggering rewrite rules:
    /// - `if` else branch must be terminal (not if/when/unless/cond)
    /// - `cond` needs 2+ regular clauses (1 clause + else becomes `if`)
    /// - `cond` else body must be terminal (not conditional)
    fn any_effect_cst(depth: u32) -> BoxedStrategy<Box<CstNode>> {
        if depth == 0 {
            any_terminal_effect_cst()
        } else {
            prop_oneof![
                any_terminal_effect_cst(),
                // (when P E)
                (any_predicate_cst(1), any_effect_cst(depth - 1))
                    .prop_map(|(p, e)| list(vec![atom("when"), p, e])),
                // (if P E1 E2) — else must be terminal
                (
                    any_predicate_cst(1),
                    any_effect_cst(depth - 1),
                    any_terminal_effect_cst()
                )
                    .prop_map(|(p, e1, e2)| list(vec![atom("if"), p, e1, e2])),
                // (cond (P1 E1) (P2 E2) ...) — 2+ clauses, no else
                prop::collection::vec(
                    (any_predicate_cst(1), any_terminal_effect_cst()),
                    2..=4
                )
                .prop_map(|clauses| {
                    let mut children = vec![atom("cond")];
                    children.extend(
                        clauses
                            .into_iter()
                            .map(|(p, e)| list(vec![p, e])),
                    );
                    list(children)
                }),
                // (cond (P1 E1) (P2 E2) ... (else TERMINAL))
                (
                    prop::collection::vec(
                        (any_predicate_cst(1), any_terminal_effect_cst()),
                        2..=4
                    ),
                    any_terminal_effect_cst()
                )
                .prop_map(|(clauses, else_eff)| {
                    let mut children = vec![atom("cond")];
                    children.extend(
                        clauses
                            .into_iter()
                            .map(|(p, e)| list(vec![p, e])),
                    );
                    children.push(list(vec![atom("else"), else_eff]));
                    list(children)
                }),
            ]
            .boxed()
        }
    }

    fn any_rule_cst() -> BoxedStrategy<Box<CstNode>> {
        (any_command_cst(), any_effect_cst(2))
            .prop_map(|(cmd, eff)| list(vec![atom("rule"), cmd, eff]))
            .boxed()
    }

    fn any_config_cst() -> BoxedStrategy<Vec<Box<CstNode>>> {
        prop::collection::vec(any_rule_cst(), 1..=4).boxed()
    }

    // ── V1 paired generators ──────────────────────────────────────────

    /// Generates (v1_forms, canonical_forms) for command rules.
    fn any_v1_command_rule() -> BoxedStrategy<(Vec<Box<CstNode>>, Vec<Box<CstNode>>)> {
        (any_command_cst(), any_effect_cst(1))
            .prop_map(|(cmd, eff)| {
                let v1 = list(vec![
                    atom("rule"),
                    list(vec![atom("command"), cmd.clone()]),
                    eff.clone(),
                ]);
                let canonical = list(vec![atom("rule"), cmd, eff]);
                (vec![v1], vec![canonical])
            })
            .boxed()
    }

    /// Generates (v1_forms, canonical_forms) for defcontext/define.
    fn any_v1_defcontext() -> BoxedStrategy<(Vec<Box<CstNode>>, Vec<Box<CstNode>>)> {
        ("[a-z][a-z0-9_-]{0,8}", any_predicate_cst(1))
            .prop_map(|(name, pred)| {
                let v1 = list(vec![atom("defcontext"), atom(&name), pred.clone()]);
                let canonical = list(vec![atom("define"), atom(&name), pred]);
                (vec![v1], vec![canonical])
            })
            .boxed()
    }

    /// Generates (v1_pred, canonical_pred) for has/fact?.
    fn any_v1_has_expr() -> BoxedStrategy<(Box<CstNode>, Box<CstNode>)> {
        any_keyword_cst()
            .prop_map(|k| {
                let v1 = list(vec![atom("has"), k.clone()]);
                let canonical = list(vec![atom("fact?"), k]);
                (v1, canonical)
            })
            .boxed()
    }

    // ── Helpers ───────────────────────────────────────────────────────

    fn serialize_forms(forms: &[Box<CstNode>]) -> String {
        forms.iter().map(|f| f.serialize()).collect::<String>()
    }

    fn serialize_forms_spaced(forms: &[Box<CstNode>]) -> String {
        forms
            .iter()
            .map(|f| f.serialize())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn configs_evaluate_equal(
        config1_text: &str,
        config2_text: &str,
        cmd: &str,
        args: &[String],
        facts: &may_i_core::ContextFacts,
    ) -> bool {
        let c1 = crate::config::parse_config(config1_text);
        let c2 = crate::config::parse_config(config2_text);
        match (c1, c2) {
            (Ok(c1), Ok(c2)) => {
                let r1 = may_i_engine::evaluate(cmd, args, &c1, facts);
                let r2 = may_i_engine::evaluate(cmd, args, &c2, facts);
                match (r1, r2) {
                    (Ok(r1), Ok(r2)) => r1.decision == r2.decision,
                    (Err(_), Err(_)) => true,
                    _ => false,
                }
            }
            (Err(_), Err(_)) => true,
            _ => false,
        }
    }

    // ── Property tests ────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn canonical_configs_are_fixed_point(forms in any_config_cst()) {
            let original_sexprs: Vec<may_i_sexpr::Sexpr> =
                forms.iter().map(|n| n.to_sexpr()).collect();

            let migrated = migrate_forms(forms);
            let migrated_sexprs: Vec<may_i_sexpr::Sexpr> =
                migrated.iter().map(|n| n.to_sexpr()).collect();

            prop_assert_eq!(
                original_sexprs.len(),
                migrated_sexprs.len(),
                "form count changed after migration"
            );

            for (orig, mig) in original_sexprs.iter().zip(migrated_sexprs.iter()) {
                prop_assert_eq!(
                    orig, mig,
                    "migration changed canonical form:\n  original: {}\n  migrated: {}",
                    orig, mig
                );
            }
        }

        #[test]
        fn migration_is_idempotent(forms in any_config_cst()) {
            let migrated_once = migrate_forms(forms);
            let once_text = serialize_forms(&migrated_once);

            let (reparsed, errors) = may_i_sexpr::cst::parse(&once_text);
            prop_assert!(errors.is_empty(), "migrated output failed to re-parse: {:?}", errors);

            let migrated_twice = migrate_forms(reparsed);
            let twice_text = serialize_forms(&migrated_twice);

            prop_assert_eq!(once_text, twice_text, "migration is not idempotent");
        }

        #[test]
        fn migration_output_is_parseable(forms in any_config_cst()) {
            let migrated = migrate_forms(forms);
            let text = serialize_forms_spaced(&migrated);
            let result = crate::config::parse_config(&text);
            prop_assert!(
                result.is_ok(),
                "migrated config failed to parse:\n  text: {}\n  error: {:?}",
                text,
                result.err()
            );
        }

        #[test]
        fn v1_command_rule_eval_preserved(
            (v1_forms, canonical_forms) in any_v1_command_rule(),
            cmd in "[a-z][a-z0-9_-]{0,10}",
        ) {
            let migrated = migrate_forms(v1_forms);
            let migrated_text = serialize_forms_spaced(&migrated);
            let canonical_text = serialize_forms_spaced(&canonical_forms);

            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());
            prop_assume!(crate::config::parse_config(&canonical_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                configs_evaluate_equal(&migrated_text, &canonical_text, &cmd, &args, &facts),
                "eval differs:\n  v1 migrated: {}\n  canonical: {}",
                migrated_text,
                canonical_text
            );
        }

        #[test]
        fn v1_defcontext_eval_preserved(
            (v1_forms, canonical_forms) in any_v1_defcontext(),
        ) {
            let migrated = migrate_forms(v1_forms);
            let migrated_sexprs: Vec<may_i_sexpr::Sexpr> =
                migrated.iter().map(|n| n.to_sexpr()).collect();
            let canonical_sexprs: Vec<may_i_sexpr::Sexpr> =
                canonical_forms.iter().map(|n| n.to_sexpr()).collect();

            prop_assert_eq!(
                migrated_sexprs, canonical_sexprs,
                "defcontext migration mismatch"
            );
        }

        #[test]
        fn v1_has_to_fact_preserved(
            (v1_pred, canonical_pred) in any_v1_has_expr(),
            cmd in "[a-z][a-z0-9_-]{0,10}",
        ) {
            let v1_rule = list(vec![
                atom("rule"),
                str_node(&cmd),
                list(vec![atom("when"), v1_pred, list(vec![atom("effect"), atom(":allow")])]),
            ]);
            let canonical_rule = list(vec![
                atom("rule"),
                str_node(&cmd),
                list(vec![atom("when"), canonical_pred, list(vec![atom("effect"), atom(":allow")])]),
            ]);

            let migrated = migrate_forms(vec![v1_rule]);
            let migrated_text = serialize_forms_spaced(&migrated);
            let canonical_text = canonical_rule.serialize();

            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());
            prop_assume!(crate::config::parse_config(&canonical_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                configs_evaluate_equal(&migrated_text, &canonical_text, &cmd, &args, &facts),
                "has→fact? eval differs:\n  v1 migrated: {}\n  canonical: {}",
                migrated_text,
                canonical_text
            );
        }

        #[test]
        fn canonical_roundtrip_preserves_eval(
            forms in any_config_cst(),
            cmd in "[a-z][a-z0-9_-]{0,10}",
        ) {
            let original_text = serialize_forms_spaced(&forms);
            let migrated = migrate_forms(forms);
            let migrated_text = serialize_forms_spaced(&migrated);

            prop_assume!(crate::config::parse_config(&original_text).is_ok());
            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                configs_evaluate_equal(&original_text, &migrated_text, &cmd, &args, &facts),
                "round-trip eval differs:\n  original: {}\n  migrated: {}",
                original_text,
                migrated_text
            );
        }

        #[test]
        fn migration_converges(forms in any_config_cst()) {
            let _migrated = migrate_forms(forms);
        }
    }
}

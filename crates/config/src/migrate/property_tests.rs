#[cfg(test)]
mod tests {
    use may_i_sexpr::test_generators::*;
    use proptest::prelude::*;

    use crate::migrate::migrate_forms;

    // ── V1 paired generators ──────────────────────────────────────────

    /// Generates (v1_forms, canonical_forms) for command rules.
    fn any_v1_command_rule() -> BoxedStrategy<(
        Vec<Box<may_i_sexpr::CstNode>>,
        Vec<Box<may_i_sexpr::CstNode>>,
    )> {
        (any_command_pattern_cst(), any_canonical_effect_cst(1))
            .prop_map(|(cmd, eff)| {
                let v1 = cst_list(vec![
                    cst_atom("rule"),
                    cst_list(vec![cst_atom("command"), cmd.clone()]),
                    eff.clone(),
                ]);
                let canonical = cst_list(vec![cst_atom("rule"), cmd, eff]);
                (vec![v1], vec![canonical])
            })
            .boxed()
    }

    /// Generates (v1_forms, canonical_forms) for defcontext/define.
    fn any_v1_defcontext() -> BoxedStrategy<(
        Vec<Box<may_i_sexpr::CstNode>>,
        Vec<Box<may_i_sexpr::CstNode>>,
    )> {
        ("[a-z][a-z0-9_-]{0,8}", any_predicate_cst(1))
            .prop_map(|(name, pred)| {
                let v1 = cst_list(vec![cst_atom("defcontext"), cst_atom(&name), pred.clone()]);
                let canonical = cst_list(vec![cst_atom("define"), cst_atom(&name), pred]);
                (vec![v1], vec![canonical])
            })
            .boxed()
    }

    /// Generates (v1_pred, canonical_pred) for has/fact?.
    fn any_v1_has_expr() -> BoxedStrategy<(Box<may_i_sexpr::CstNode>, Box<may_i_sexpr::CstNode>)> {
        any_keyword_cst()
            .prop_map(|k| {
                let v1 = cst_list(vec![cst_atom("has"), k.clone()]);
                let canonical = cst_list(vec![cst_atom("fact?"), k]);
                (v1, canonical)
            })
            .boxed()
    }

    // ── Compound V1 generators ─────────────────────────────────────────

    /// Generates a v1 rule with `(context PRED)`: `(rule (command CMD) (context PRED) (effect ...))`.
    fn any_v1_rule_with_context() -> BoxedStrategy<(
        Vec<Box<may_i_sexpr::CstNode>>,
        Vec<Box<may_i_sexpr::CstNode>>,
    )> {
        (
            any_command_pattern_cst(),
            any_predicate_cst(1),
            any_terminal_effect_cst(),
        )
            .prop_map(|(cmd, pred, eff)| {
                let v1 = cst_list(vec![
                    cst_atom("rule"),
                    cst_list(vec![cst_atom("command"), cmd.clone()]),
                    cst_list(vec![cst_atom("context"), pred.clone()]),
                    eff.clone(),
                ]);
                let canonical = cst_list(vec![
                    cst_atom("rule"),
                    cmd,
                    cst_list(vec![cst_atom("when"), pred, eff]),
                ]);
                (vec![v1], vec![canonical])
            })
            .boxed()
    }

    /// Generates a v1 rule with `(args (positional ...))`:
    /// `(rule (command CMD) (args (positional PAT)) (effect ...))`.
    fn any_v1_rule_with_args() -> BoxedStrategy<(Vec<Box<may_i_sexpr::CstNode>>, String)> {
        (
            any_command_pattern_cst(),
            "[a-z][a-z0-9_-]{0,8}".prop_map(|s| cst_str(&s)),
            any_terminal_effect_cst(),
        )
            .prop_map(|(cmd, arg_pat, eff)| {
                let v1 = cst_list(vec![
                    cst_atom("rule"),
                    cst_list(vec![cst_atom("command"), cmd.clone()]),
                    cst_list(vec![
                        cst_atom("args"),
                        cst_list(vec![cst_atom("positional"), arg_pat]),
                    ]),
                    eff,
                ]);
                let cmd_text = cmd.serialize();
                // Trim quotes from string literal for eval command
                let cmd_str = cmd_text.trim_matches('"').to_string();
                (vec![v1], cmd_str)
            })
            .boxed()
    }

    /// Generates a compound v1 rule with command + context + args:
    /// `(rule (command CMD) (context PRED) (args (positional PAT)) (effect ...))`.
    fn any_v1_compound_rule() -> BoxedStrategy<(Vec<Box<may_i_sexpr::CstNode>>, String)> {
        (
            any_command_pattern_cst(),
            any_predicate_cst(0),
            "[a-z][a-z0-9_-]{0,8}".prop_map(|s| cst_str(&s)),
            any_terminal_effect_cst(),
        )
            .prop_map(|(cmd, pred, arg_pat, eff)| {
                let v1 = cst_list(vec![
                    cst_atom("rule"),
                    cst_list(vec![cst_atom("command"), cmd.clone()]),
                    cst_list(vec![cst_atom("context"), pred]),
                    cst_list(vec![
                        cst_atom("args"),
                        cst_list(vec![cst_atom("positional"), arg_pat]),
                    ]),
                    eff,
                ]);
                let cmd_text = cmd.serialize();
                let cmd_str = cmd_text.trim_matches('"').to_string();
                (vec![v1], cmd_str)
            })
            .boxed()
    }

    // ── V1 wrapper generator ──────────────────────────────────────────

    /// Generates (v1_wrapper_forms, expected_command) for wrapper migration.
    /// Wrapper form: `(wrapper CMD (positional PAT ... :command+args))`
    /// Migrates to:  `(rule CMD (positional PAT ... . (may-i *)))`
    fn any_v1_wrapper() -> BoxedStrategy<(Vec<Box<may_i_sexpr::CstNode>>, String)> {
        (
            any_command_pattern_cst(),
            prop::collection::vec("[a-z][a-z0-9_-]{0,6}".prop_map(|s| cst_str(&s)), 0..3),
        )
            .prop_map(|(cmd, pats)| {
                let mut pos_children = vec![cst_atom("positional")];
                pos_children.extend(pats);
                pos_children.push(cst_atom(":command+args"));

                let v1 = cst_list(vec![
                    cst_atom("wrapper"),
                    cmd.clone(),
                    cst_list(pos_children),
                ]);
                let cmd_text = cmd.serialize();
                let cmd_str = cmd_text.trim_matches('"').to_string();
                (vec![v1], cmd_str)
            })
            .boxed()
    }

    // ── V1 config generator (mixed forms) ───────────────────────────

    /// Generates a (v1_forms, canonical_forms) pair mixing command rules,
    /// defcontexts, and has→fact? rewrites.
    fn any_v1_config() -> BoxedStrategy<(
        Vec<Box<may_i_sexpr::CstNode>>,
        Vec<Box<may_i_sexpr::CstNode>>,
    )> {
        prop::collection::vec(
            prop_oneof![
                any_v1_command_rule(),
                any_v1_defcontext(),
                any_v1_rule_with_context(),
            ],
            1..4,
        )
        .prop_map(|pairs| {
            let mut all_v1 = Vec::new();
            let mut all_canonical = Vec::new();
            for (v1, canonical) in pairs {
                all_v1.extend(v1);
                all_canonical.extend(canonical);
            }
            (all_v1, all_canonical)
        })
        .boxed()
    }

    // ── Canonical config with defines ────────────────────────────────

    /// Generates a canonical define: `(define name (fact? :key))`.
    fn any_canonical_define_cst() -> BoxedStrategy<Box<may_i_sexpr::CstNode>> {
        ("[a-z][a-z0-9_-]{0,8}", any_predicate_cst(0))
            .prop_map(|(name, pred)| cst_list(vec![cst_atom("define"), cst_atom(&name), pred]))
            .boxed()
    }

    /// Generates a canonical config with both defines and rules that reference them.
    fn any_canonical_config_with_defines() -> BoxedStrategy<Vec<Box<may_i_sexpr::CstNode>>> {
        (
            prop::collection::vec(any_canonical_define_cst(), 1..=3),
            prop::collection::vec(any_canonical_rule_cst(), 1..=3),
        )
            .prop_map(|(defines, rules)| {
                let mut forms = defines;
                forms.extend(rules);
                forms
            })
            .boxed()
    }

    // ── Helpers ───────────────────────────────────────────────────────

    fn serialize_forms(forms: &[Box<may_i_sexpr::CstNode>]) -> String {
        forms.iter().map(|f| f.serialize()).collect::<String>()
    }

    fn serialize_forms_spaced(forms: &[Box<may_i_sexpr::CstNode>]) -> String {
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

    /// Parse v1 forms through migration pipeline, returning canonical text.
    fn migrate_v1_to_text(v1_forms: Vec<Box<may_i_sexpr::CstNode>>) -> String {
        let migrated = migrate_forms(v1_forms);
        serialize_forms_spaced(&migrated)
    }

    /// Check eval equivalence for a migrated config (parsed through migration
    /// pipeline) against a given command, using resolve for named predicates.
    fn migrated_config_evaluates_ok(
        migrated_text: &str,
        cmd: &str,
        args: &[String],
        facts: &may_i_core::ContextFacts,
    ) -> bool {
        let config = match crate::config::parse_config(migrated_text) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let resolved = match crate::resolve::validate_and_resolve(&config.rules, &config.defines) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let mut config = config;
        config.rules = resolved;
        may_i_engine::evaluate(cmd, args, &config, facts).is_ok()
    }

    // ── Property tests ────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn canonical_configs_are_fixed_point(forms in any_canonical_config_cst()) {
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
        fn migration_is_idempotent(forms in any_canonical_config_cst()) {
            let migrated_once = migrate_forms(forms);
            let once_text = serialize_forms(&migrated_once);

            let (reparsed, errors) = may_i_sexpr::cst::parse(&once_text);
            prop_assert!(errors.is_empty(), "migrated output failed to re-parse: {:?}", errors);

            let migrated_twice = migrate_forms(reparsed);
            let twice_text = serialize_forms(&migrated_twice);

            prop_assert_eq!(once_text, twice_text, "migration is not idempotent");
        }

        #[test]
        fn migration_output_is_parseable(forms in any_canonical_config_cst()) {
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
            let v1_rule = cst_list(vec![
                cst_atom("rule"),
                cst_str(&cmd),
                cst_list(vec![cst_atom("when"), v1_pred, cst_list(vec![cst_atom("effect"), cst_atom(":allow")])]),
            ]);
            let canonical_rule = cst_list(vec![
                cst_atom("rule"),
                cst_str(&cmd),
                cst_list(vec![cst_atom("when"), canonical_pred, cst_list(vec![cst_atom("allow")])]),
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
            forms in any_canonical_config_cst(),
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
        fn migration_converges(forms in any_canonical_config_cst()) {
            let _migrated = migrate_forms(forms);
        }

        // ── Compound V1 property tests ──────────────────────────────────

        #[test]
        fn v1_rule_with_context_eval_preserved(
            (v1_forms, canonical_forms) in any_v1_rule_with_context(),
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
                "context eval differs:\n  v1 migrated: {}\n  canonical: {}",
                migrated_text,
                canonical_text
            );
        }

        #[test]
        fn v1_rule_with_args_migrates_and_evaluates(
            (v1_forms, cmd_str) in any_v1_rule_with_args(),
        ) {
            let migrated_text = migrate_v1_to_text(v1_forms);
            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                migrated_config_evaluates_ok(&migrated_text, &cmd_str, &args, &facts),
                "args rule failed to evaluate after migration:\n  text: {}",
                migrated_text
            );
        }

        #[test]
        fn v1_wrapper_migrates_and_evaluates(
            (v1_forms, cmd_str) in any_v1_wrapper(),
        ) {
            let migrated_text = migrate_v1_to_text(v1_forms);
            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                migrated_config_evaluates_ok(&migrated_text, &cmd_str, &args, &facts),
                "wrapper rule failed to evaluate after migration:\n  text: {}",
                migrated_text
            );
        }

        #[test]
        fn v1_config_eval_preserved(
            (v1_forms, canonical_forms) in any_v1_config(),
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
                "mixed config eval differs:\n  v1 migrated: {}\n  canonical: {}",
                migrated_text,
                canonical_text
            );
        }

        #[test]
        fn v1_compound_rule_migrates_and_evaluates(
            (v1_forms, cmd_str) in any_v1_compound_rule(),
        ) {
            let migrated_text = migrate_v1_to_text(v1_forms);
            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                migrated_config_evaluates_ok(&migrated_text, &cmd_str, &args, &facts),
                "compound rule failed to evaluate after migration:\n  text: {}",
                migrated_text
            );
        }

        // ── Migration with defines ──────────────────────────────────────

        #[test]
        fn migration_preserves_defines(forms in any_canonical_config_with_defines()) {
            let original_text = serialize_forms_spaced(&forms);
            let migrated = migrate_forms(forms);
            let migrated_text = serialize_forms_spaced(&migrated);

            prop_assume!(crate::config::parse_config(&original_text).is_ok());
            prop_assume!(crate::config::parse_config(&migrated_text).is_ok());

            let args: Vec<String> = vec![];
            let facts = may_i_core::ContextFacts::default();
            prop_assert!(
                configs_evaluate_equal(&original_text, &migrated_text, "test-cmd", &args, &facts),
                "migration with defines changed eval:\n  original: {}\n  migrated: {}",
                original_text,
                migrated_text
            );
        }

        #[test]
        fn migration_with_defines_is_idempotent(forms in any_canonical_config_with_defines()) {
            let migrated_once = migrate_forms(forms);
            let once_text = serialize_forms(&migrated_once);

            let (reparsed, errors) = may_i_sexpr::cst::parse(&once_text);
            prop_assert!(errors.is_empty(), "migrated output failed to re-parse: {:?}", errors);

            let migrated_twice = migrate_forms(reparsed);
            let twice_text = serialize_forms(&migrated_twice);

            prop_assert_eq!(once_text, twice_text, "migration with defines is not idempotent");
        }
    }
}

#[cfg(test)]
mod tests {
    use may_i_sexpr::test_generators::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn parse_effect_never_panics_on_canonical(cst in any_canonical_effect_cst(2)) {
            let sexpr = cst.to_sexpr();
            let _ = crate::parse_effect(&sexpr);
        }

        #[test]
        fn parse_effect_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::parse_effect(&sexpr);
        }

        #[test]
        fn parse_predicate_never_panics_on_generated(cst in any_predicate_cst(2)) {
            let sexpr = cst.to_sexpr();
            let _ = crate::parse_predicate(&sexpr);
        }

        #[test]
        fn parse_predicate_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::parse_predicate(&sexpr);
        }

        #[test]
        fn parse_command_pattern_never_panics_on_generated(cst in any_command_pattern_cst()) {
            let sexpr = cst.to_sexpr();
            let _ = crate::parse_command_pattern(&sexpr);
        }

        #[test]
        fn parse_command_pattern_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::parse_command_pattern(&sexpr);
        }

        #[test]
        fn parse_rule_never_panics_on_generated(cst in any_canonical_rule_cst()) {
            let sexpr = cst.to_sexpr();
            let _ = crate::parse_rule(&sexpr);
        }

        #[test]
        fn parse_rule_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::parse_rule(&sexpr);
        }

        // Form-list parser body must accept any (style …) name + optional
        // (flag …)/(parameter …) declarations without panicking.
        #[test]
        fn parse_parser_form_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::parser_form::parse_parser_form(&sexpr);
        }

        #[test]
        fn parse_parser_form_accepts_minimal(
            program in "[a-z][a-z-]{0,8}",
            style in prop_oneof!["gnu", "single-dash-long", "legacy-bundle", "key-value"]
        ) {
            let text = format!(r#"(parser "{program}" (style {style}))"#);
            let (forms, errs) = may_i_sexpr::parse(&text);
            prop_assert!(errs.is_empty());
            let form = forms.into_iter().next().unwrap();
            let parsed = crate::parser_form::parse_parser_form(&form);
            prop_assert!(parsed.is_ok(), "parse failed: {:?}", parsed.err());
            let parsed = parsed.unwrap();
            prop_assert_eq!(parsed.program, program);
            prop_assert_eq!(parsed.style_name, style.to_string());
        }
    }
}

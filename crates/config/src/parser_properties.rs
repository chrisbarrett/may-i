#[cfg(test)]
mod tests {
    use may_i_sexpr::test_generators::*;
    use proptest::prelude::*;

    // ── parser-named-bindings: new-form generators ──────────────────

    /// A binding atom string ("#name") for use inside generated bodies.
    fn binding_atom() -> impl Strategy<Value = String> {
        "#[a-z][a-z0-9_]{0,6}".prop_map(String::from)
    }

    /// `(flags MODE)` declaration.
    fn flags_decl() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("(flags posix)".to_string()),
            Just("(flags permute)".to_string()),
            prop::collection::vec("\"[a-z-]{1,5}\"", 1..3)
                .prop_map(|toks| format!("(flags (until {}))", toks.join(" "))),
        ]
    }

    /// `(rest #var)` declaration.
    fn rest_decl() -> impl Strategy<Value = String> {
        binding_atom().prop_map(|b| format!("(rest {b})"))
    }

    /// `(positional [#var] PAT [QUANT])` declaration. PAT is constrained
    /// to a regex literal or `*` to keep generated bodies parseable.
    fn positional_decl() -> impl Strategy<Value = String> {
        let pat = prop_oneof![Just("*".to_string()), Just(r#"(regex "^x.*")"#.to_string()),];
        let quant = prop_oneof![
            Just("".to_string()),
            Just(" ?".to_string()),
            Just(" *".to_string()),
            Just(" +".to_string())
        ];
        let binding = prop_oneof![
            Just("".to_string()),
            binding_atom().prop_map(|b| format!("{b} ")),
        ];
        (binding, pat, quant).prop_map(|(b, p, q)| format!("(positional {b}{p}{q})"))
    }

    /// `(parameter NAME [#var])` short form.
    fn parameter_decl() -> impl Strategy<Value = String> {
        let name = "\"[a-z][a-z]{0,3}\"";
        let trailing = prop_oneof![
            Just("".to_string()),
            binding_atom().prop_map(|b| format!(" {b}")),
        ];
        (name, trailing).prop_map(|(n, t)| format!("(parameter {n}{t})"))
    }

    /// Assemble a complete `(parser …)` form with new-style body items.
    ///
    /// Distinct bindings per body to avoid the parser's
    /// duplicate-binding rejection; assembled in deliberately shuffled
    /// order to exercise canonicalisation.
    fn new_form_parser() -> impl Strategy<Value = String> {
        (
            flags_decl(),
            proptest::option::of(rest_decl()),
            prop::collection::vec(positional_decl(), 0..3),
            prop::collection::vec(parameter_decl(), 0..3),
        )
            .prop_map(|(flags, rest, positionals, parameters)| {
                let mut body: Vec<String> = vec!["(style gnu)".to_string(), flags];
                body.extend(parameters);
                body.extend(positionals);
                if let Some(r) = rest {
                    body.push(r);
                }
                format!("(parser \"prog\" {})", body.join(" "))
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn parse_effect_never_panics_on_canonical(cst in any_canonical_effect_cst(2)) {
            let sexpr = cst.to_sexpr();
            let _ = crate::effect::parse_effect(&sexpr);
        }

        #[test]
        fn parse_effect_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::effect::parse_effect(&sexpr);
        }

        // parse_rule_body is the only public entry point for rule-body
        // parsing; it forwards to crate::effect::parse_effect. The two
        // SHALL produce structurally equal results on every input.
        #[test]
        fn parse_rule_body_agrees_with_parse_effect_on_canonical(
            cst in any_canonical_effect_cst(2)
        ) {
            let sexpr = cst.to_sexpr();
            let via_body = crate::parse_rule_body(&sexpr);
            let via_effect = crate::effect::parse_effect(&sexpr);
            prop_assert_eq!(format!("{:?}", via_body), format!("{:?}", via_effect));
        }

        #[test]
        fn parse_rule_body_agrees_with_parse_effect_on_arbitrary(sexpr in any_sexpr(3)) {
            let via_body = crate::parse_rule_body(&sexpr);
            let via_effect = crate::effect::parse_effect(&sexpr);
            prop_assert_eq!(format!("{:?}", via_body), format!("{:?}", via_effect));
        }

        #[test]
        fn parse_predicate_never_panics_on_generated(cst in any_predicate_cst(2)) {
            let sexpr = cst.to_sexpr();
            let _ = crate::predicate::parse_predicate(&sexpr);
        }

        #[test]
        fn parse_predicate_never_panics_on_arbitrary(sexpr in any_sexpr(3)) {
            let _ = crate::predicate::parse_predicate(&sexpr);
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

        // ── Section 3.11 checkpoint: canonicalisation algebra ────────

        /// Stability: parse → canonicalise → parse yields equal ASTs.
        #[test]
        fn new_form_canonicalise_parse_stable(text in new_form_parser()) {
            use may_i_sexpr::parse_cst;
            use crate::canonicalise::canonicalise_forms;
            let (forms, errs) = parse_cst(&text);
            prop_assume!(errs.is_empty());

            let original = crate::parser_form::parse_parser_form(&forms[0].to_sexpr());
            prop_assume!(original.is_ok());
            let original = original.unwrap();

            let canon = canonicalise_forms(forms);
            let canon_text: String = canon.iter().map(|n| n.serialize()).collect();
            let (re_forms, re_errs) = may_i_sexpr::parse(&canon_text);
            prop_assert!(re_errs.is_empty(), "canon reparse errors: {:?}", re_errs);
            let reparsed = crate::parser_form::parse_parser_form(&re_forms[0])
                .expect("canonical form must reparse");

            prop_assert_eq!(&original.flags_mode, &reparsed.flags_mode);
            prop_assert_eq!(
                original.rest.as_ref().map(|b| b.as_str().to_string()),
                reparsed.rest.as_ref().map(|b| b.as_str().to_string())
            );
            prop_assert_eq!(original.parameters.len(), reparsed.parameters.len());
            prop_assert_eq!(original.positionals.len(), reparsed.positionals.len());
            prop_assert_eq!(original.flags.len(), reparsed.flags.len());
        }

        /// Idempotence: canonicalise twice == canonicalise once.
        #[test]
        fn new_form_canonicalise_idempotent(text in new_form_parser()) {
            use may_i_sexpr::parse_cst;
            use crate::canonicalise::canonicalise_forms;
            let (forms, errs) = parse_cst(&text);
            prop_assume!(errs.is_empty());

            let once = canonicalise_forms(forms);
            let once_text: String = once.iter().map(|n| n.serialize()).collect();
            let (reparsed, re_errs) = parse_cst(&once_text);
            prop_assume!(re_errs.is_empty());
            let twice = canonicalise_forms(reparsed);
            let twice_text: String = twice.iter().map(|n| n.serialize()).collect();
            prop_assert_eq!(once_text, twice_text);
        }

        /// Invariant survival: a body declaring (flags) twice MUST be
        /// rejected by the parser — canonicalisation does not silently
        /// merge duplicates.
        #[test]
        fn duplicate_flags_always_rejected(mode in flags_decl()) {
            let text = format!("(parser \"x\" (style gnu) {mode} {mode})");
            let (forms, errs) = may_i_sexpr::parse(&text);
            prop_assume!(errs.is_empty());
            let parsed = crate::parser_form::parse_parser_form(&forms[0]);
            prop_assert!(parsed.is_err(), "duplicate (flags) must be rejected");
        }

        /// Invariant survival: duplicate (rest …) is rejected.
        #[test]
        fn duplicate_rest_always_rejected(a in binding_atom(), b in binding_atom()) {
            prop_assume!(a != b);
            let text = format!(
                "(parser \"x\" (style gnu) (flags posix) (rest {a}) (rest {b}))"
            );
            let (forms, errs) = may_i_sexpr::parse(&text);
            prop_assume!(errs.is_empty());
            let parsed = crate::parser_form::parse_parser_form(&forms[0]);
            prop_assert!(parsed.is_err(), "duplicate (rest) must be rejected");
        }
    }
}

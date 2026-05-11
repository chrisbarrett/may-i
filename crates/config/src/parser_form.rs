// Parser for `(parser PROGRAM (style STYLE) BODY…)` forms.
//
// BODY items are a uniform list of declaration forms:
//   (style STYLE)         — exactly one, required
//   (flag NAME)           — zero or more
//   (parameter NAME [F])  — zero or more
//
// NAME: a string (single spelling) or [short long] vector (two
// spellings). The optional FORM after a parameter name is a treatment
// declaration; in v2 only `(authorise)` is accepted (the new
// `(authorise)` verb arrives in a later slice of the dsl-coherence
// change).

use may_i_core::ast::{
    BindingName, Capture, FlagsMode, ParameterDecl, ParameterTreatment, Parser, PositionalDecl,
    Provenance,
};
use may_i_core::pattern::Quantifier;
use may_i_sexpr::{RawError, Sexpr};

/// Parse a top-level `(parser PROGRAM (style STYLE) BODY…)` form.
pub fn parse_parser_form(sexpr: &Sexpr) -> Result<Parser, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("parser form must be a list", sexpr.span()))?;

    if list.len() < 3 {
        return Err(RawError::new(
            "parser requires a program and a (style …) declaration",
            sexpr.span(),
        )
        .with_help("(parser \"git\" (style gnu) (flag \"v\") …)"));
    }

    let program = list[1]
        .as_atom_or_str()
        .ok_or_else(|| RawError::new("parser program must be a string", list[1].span()))?
        .to_string();

    let mut style_name: Option<String> = None;
    let mut flags: Vec<Vec<String>> = Vec::new();
    let mut parameters: Vec<ParameterDecl> = Vec::new();
    let mut positionals: Vec<PositionalDecl> = Vec::new();
    let mut declared_flags_mode: Option<FlagsMode> = None;
    let mut rest_binding: Option<BindingName> = None;
    let mut declared_names: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    let mut declared_bindings: std::collections::HashSet<String> = std::collections::HashSet::new();

    for item in &list[2..] {
        let item_list = item
            .as_list()
            .ok_or_else(|| RawError::new("parser body items must be lists", item.span()))?;
        if item_list.is_empty() {
            return Err(RawError::new("empty parser body item", item.span()));
        }
        let tag = item_list[0].as_atom().ok_or_else(|| {
            RawError::new("parser body item tag must be an atom", item_list[0].span())
        })?;
        match tag {
            "style" => {
                if style_name.is_some() {
                    return Err(RawError::new(
                        "parser body declares (style …) more than once",
                        item.span(),
                    ));
                }
                if item_list.len() != 2 {
                    return Err(RawError::new(
                        "(style …) takes exactly one style name",
                        item.span(),
                    ));
                }
                let name = item_list[1].as_atom().ok_or_else(|| {
                    RawError::new("style name must be an atom", item_list[1].span())
                })?;
                style_name = Some(name.to_string());
            }
            "flag" => {
                let names = parse_names(&item_list[1..], "flag", item.span())?;
                check_dup(
                    &names,
                    "flag",
                    &mut declared_names,
                    &mut flags,
                    &mut parameters,
                    item.span(),
                )?;
                flags.push(names);
            }
            "parameter" => {
                if item_list.len() < 2 {
                    return Err(RawError::new("parameter requires a name", item.span()));
                }
                let names = parse_name(&item_list[1])?;
                // Trailing `#var` slot (introduced by parser-named-bindings):
                // `(parameter NAME [FORM] [#var])`. Detect by trailing
                // binding atom; consume it and shrink the FORM window.
                let (form_end, binding) = match item_list.last() {
                    Some(last) if matches!(last, Sexpr::Binding(_, _)) => {
                        let bn = parse_binding_atom(last)?;
                        record_binding(&bn, last.span(), &mut declared_bindings)?;
                        (item_list.len() - 1, Some(bn))
                    }
                    _ => (item_list.len(), None),
                };
                let (treatment, capture) = if form_end >= 3 {
                    parse_parameter_body(&item_list[2])?
                } else {
                    (ParameterTreatment::None, Capture::Single)
                };
                if form_end > 3 {
                    return Err(RawError::new(
                        "parameter accepts at most one FORM after the name (optionally followed by a #var binding)",
                        item.span(),
                    ));
                }
                check_dup(
                    &names,
                    "parameter",
                    &mut declared_names,
                    &mut flags,
                    &mut parameters,
                    item.span(),
                )?;
                parameters.push(ParameterDecl {
                    names,
                    treatment,
                    capture,
                    binding,
                });
            }
            "flags" => {
                if declared_flags_mode.is_some() {
                    return Err(RawError::new(
                        "parser body declares (flags …) more than once",
                        item.span(),
                    ));
                }
                declared_flags_mode = Some(parse_flags_mode(&item_list[1..], item.span())?);
            }
            "rest" => {
                if rest_binding.is_some() {
                    return Err(RawError::new(
                        "parser body declares (rest …) more than once",
                        item.span(),
                    ));
                }
                if item_list.len() != 2 {
                    return Err(RawError::new(
                        "(rest #var) takes exactly one binding-name argument",
                        item.span(),
                    )
                    .with_help("(rest #cmd)"));
                }
                let bn = parse_binding_atom(&item_list[1])?;
                record_binding(&bn, item_list[1].span(), &mut declared_bindings)?;
                rest_binding = Some(bn);
            }
            "positional" => {
                positionals.push(parse_positional_decl(
                    &item_list[1..],
                    item.span(),
                    &mut declared_bindings,
                )?);
            }
            "tail" => {
                return Err(RawError::new(
                    "legacy `(tail …)` parser-body form is retired",
                    item.span(),
                )
                .with_help(
                    "rewrite as `(flags MODE) (rest #cmd)` — \
                     `(tail (after :flags))` → `(flags posix) (rest #cmd)`, \
                     `(tail (after \"TOK\"))` → `(flags (until \"TOK\")) (rest #cmd)`",
                ));
            }
            other => {
                return Err(RawError::new(
                    format!("unknown parser body item: {other}"),
                    item.span(),
                )
                .with_help(
                    "body items: (style …), (flags …), (flag NAME), (parameter NAME [FORM] [#var]), (positional [#var] PAT [QUANT]), (rest #var)",
                ));
            }
        }
    }

    let style_name = style_name.ok_or_else(|| {
        RawError::new(
            "parser body must declare exactly one (style …) form",
            sexpr.span(),
        )
        .with_help("(parser \"git\" (style gnu) …)")
    })?;

    // `(flags MODE)` is the source of truth. Parsers without an
    // explicit declaration default to permute (the historic behaviour
    // for parsers without a wrapper-boundary).
    let flags_mode = declared_flags_mode.unwrap_or(FlagsMode::Permute);
    Ok(Parser {
        program,
        style_name,
        flags,
        parameters,
        positionals,
        flags_mode,
        rest: rest_binding,
        span: sexpr.span(),
        provenance: Provenance::PrimaryConfig,
    })
}

/// Parse a `#var` binding atom into a [`BindingName`], surfacing the
/// smart-constructor error as a `RawError` anchored at the surface
/// span.
fn parse_binding_atom(sexpr: &Sexpr) -> Result<BindingName, RawError> {
    let raw = sexpr
        .as_binding()
        .ok_or_else(|| RawError::new("expected a binding atom (e.g. #cmd)", sexpr.span()))?;
    BindingName::parse(raw)
        .map_err(|e| RawError::new(format!("invalid binding name: {e}"), sexpr.span()))
}

fn record_binding(
    bn: &BindingName,
    span: may_i_core::Span,
    declared: &mut std::collections::HashSet<String>,
) -> Result<(), RawError> {
    if !declared.insert(bn.as_str().to_string()) {
        return Err(RawError::new(
            format!("binding `{bn}` declared more than once in parser body"),
            span,
        ));
    }
    Ok(())
}

/// Parse `(flags MODE)` arguments. Three shapes:
/// - `posix`           — POSIX `(flags posix)`.
/// - `permute`         — GNU `(flags permute)`.
/// - `(until "STR" …)` — `(flags (until "--"))` / `(flags (until "--command" "-c"))`.
fn parse_flags_mode(args: &[Sexpr], span: may_i_core::Span) -> Result<FlagsMode, RawError> {
    if args.len() != 1 {
        return Err(
            RawError::new("(flags …) takes exactly one MODE argument", span)
                .with_help("(flags posix) | (flags permute) | (flags (until \"--\"))"),
        );
    }
    let arg = &args[0];
    if let Some(atom) = arg.as_atom() {
        match atom {
            "posix" => return Ok(FlagsMode::Posix),
            "permute" => return Ok(FlagsMode::Permute),
            other => {
                return Err(RawError::new(
                    format!("unknown flag-scanning mode: {other}"),
                    arg.span(),
                )
                .with_help("modes: posix, permute, (until \"--\")"));
            }
        }
    }
    let list = arg.as_list().ok_or_else(|| {
        RawError::new(
            "MODE must be `posix`, `permute`, or `(until STR…)`",
            arg.span(),
        )
    })?;
    let head = list
        .first()
        .and_then(Sexpr::as_atom)
        .ok_or_else(|| RawError::new("MODE list must start with `until`", arg.span()))?;
    if head != "until" {
        return Err(RawError::new(
            format!("unknown flag-scanning mode head: {head}"),
            arg.span(),
        )
        .with_help("only `(until STR…)` is supported in list form"));
    }
    if list.len() < 2 {
        return Err(RawError::new(
            "(until STR…) requires at least one boundary token",
            arg.span(),
        ));
    }
    let mut tokens = Vec::with_capacity(list.len() - 1);
    for item in &list[1..] {
        let s = item.as_str().ok_or_else(|| {
            RawError::new("(until …) entries must be string literals", item.span())
        })?;
        tokens.push(s.to_string());
    }
    Ok(FlagsMode::Until(tokens))
}

/// Parse a `(positional [#var] PAT [QUANT])` declaration. Shapes:
///
/// - `(positional PAT)`         — required, one match
/// - `(positional PAT QUANT)`   — required, quantified
/// - `(positional #var PAT)`    — bound, one match
/// - `(positional #var PAT QUANT)` — bound, quantified
fn parse_positional_decl(
    args: &[Sexpr],
    span: may_i_core::Span,
    declared_bindings: &mut std::collections::HashSet<String>,
) -> Result<PositionalDecl, RawError> {
    if args.is_empty() {
        return Err(
            RawError::new("(positional …) requires at least a pattern", span)
                .with_help("(positional [#var] PAT [QUANT])"),
        );
    }
    let (binding, rest) = if matches!(args[0], Sexpr::Binding(_, _)) {
        let bn = parse_binding_atom(&args[0])?;
        record_binding(&bn, args[0].span(), declared_bindings)?;
        (Some(bn), &args[1..])
    } else {
        (None, args)
    };
    if rest.is_empty() {
        return Err(RawError::new(
            "(positional …) requires a pattern after the optional binding",
            span,
        ));
    }
    if rest.len() > 2 {
        return Err(RawError::new(
            "(positional …) takes at most PAT and an optional QUANT",
            span,
        )
        .with_help("(positional [#var] PAT [?|*|+|one])"));
    }
    let pattern = crate::pattern::parse_expr_for_capture(&rest[0])?;
    let quantifier = if rest.len() == 2 {
        parse_quantifier(&rest[1])?
    } else {
        Quantifier::One
    };
    Ok(PositionalDecl {
        binding,
        pattern,
        quantifier,
    })
}

fn parse_quantifier(sexpr: &Sexpr) -> Result<Quantifier, RawError> {
    let atom = sexpr.as_atom().ok_or_else(|| {
        RawError::new(
            "quantifier must be a bare symbol (one, ?, *, +)",
            sexpr.span(),
        )
    })?;
    match atom {
        "one" => Ok(Quantifier::One),
        "?" => Ok(Quantifier::Optional),
        "*" => Ok(Quantifier::ZeroOrMore),
        "+" => Ok(Quantifier::OneOrMore),
        other => Err(
            RawError::new(format!("unknown quantifier: {other}"), sexpr.span())
                .with_help("quantifiers: one, ?, *, +"),
        ),
    }
}

/// Parse a single NAME — either a string atom or a `[short long]` vector.
fn parse_name(sexpr: &Sexpr) -> Result<Vec<String>, RawError> {
    if sexpr.is_vector() {
        let items = sexpr.as_list().expect("vector backs a list view");
        if items.is_empty() {
            return Err(RawError::new(
                "name vector must have at least one spelling",
                sexpr.span(),
            ));
        }
        let mut names = Vec::with_capacity(items.len());
        for item in items {
            let s = item
                .as_atom_or_str()
                .ok_or_else(|| RawError::new("name spellings must be strings", item.span()))?;
            names.push(s.to_string());
        }
        Ok(names)
    } else if let Some(s) = sexpr.as_atom_or_str() {
        Ok(vec![s.to_string()])
    } else {
        Err(RawError::new(
            "name must be a string or [short long] vector",
            sexpr.span(),
        ))
    }
}

/// Parse a (flag …) body's name slots. (flag NAME) takes one NAME, but
/// historically some code paths might pass multiple — keep flexible by
/// accepting one slot only.
fn parse_names(args: &[Sexpr], tag: &str, span: may_i_core::Span) -> Result<Vec<String>, RawError> {
    if args.len() != 1 {
        return Err(RawError::new(
            format!("{tag} requires exactly one NAME"),
            span,
        ));
    }
    parse_name(&args[0])
}

/// Parse the optional body slot after `(parameter NAME …)` in a parser
/// declaration. The body is exactly one form, and its head determines
/// whether it sets the value treatment or the capture-shape:
///
/// - `(authorise)` — value treatment is [`ParameterTreatment::Authorise`].
/// - `(many-till PAT)` — capture-shape is multi-token until PAT matches.
fn parse_parameter_body(sexpr: &Sexpr) -> Result<(ParameterTreatment, Capture), RawError> {
    let list = sexpr.as_list().ok_or_else(|| {
        RawError::new(
            "parameter FORM must be a list, e.g. (authorise) or (many-till …)",
            sexpr.span(),
        )
    })?;
    if list.is_empty() {
        return Err(RawError::new("empty parameter FORM", sexpr.span()));
    }
    let head = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("parameter FORM tag must be an atom", list[0].span()))?;
    match head {
        "authorise" => {
            if list.len() != 1 {
                return Err(RawError::new(
                    "(authorise) takes no arguments",
                    sexpr.span(),
                ));
            }
            Ok((ParameterTreatment::Authorise, Capture::Single))
        }
        "may-i" => Err(RawError::new(
            "(may-i …) is retired; use (authorise) inside the parameter body",
            list[0].span(),
        )
        .with_help("run `may-i migrate` to convert legacy syntax")),
        "many-till" => {
            if list.len() != 2 {
                return Err(RawError::new(
                    "(many-till PAT) takes exactly one terminator pattern",
                    sexpr.span(),
                ));
            }
            let terminator = crate::pattern::parse_expr_for_capture(&list[1])?;
            Ok((ParameterTreatment::None, Capture::ManyTill { terminator }))
        }
        other => Err(
            RawError::new(format!("unsupported parameter FORM: {other}"), sexpr.span())
                .with_help("use (authorise) or (many-till PAT)"),
        ),
    }
}

/// Check duplicate spelling within this parser body. Last-wins is the
/// design, but we want a warning. Mismatched flag/parameter for the same
/// name is an error (irreconcilable).
fn check_dup(
    names: &[String],
    kind: &'static str,
    declared: &mut std::collections::HashMap<String, &'static str>,
    flags: &mut Vec<Vec<String>>,
    parameters: &mut Vec<ParameterDecl>,
    span: may_i_core::Span,
) -> Result<(), RawError> {
    for n in names {
        if let Some(prev_kind) = declared.get(n) {
            if *prev_kind != kind {
                return Err(RawError::new(
                    format!("name `{n}` declared as both flag and parameter — pick one"),
                    span,
                ));
            }
            // Same kind: last-wins, drop the earlier declaration that
            // contained this name.
            eprintln!("warning: duplicate {kind} declaration for `{n}` — last declaration wins");
            if kind == "flag" {
                flags.retain(|spellings| !spellings.iter().any(|s| s == n));
            } else {
                parameters.retain(|p| !p.names.iter().any(|s| s == n));
            }
        }
        declared.insert(n.clone(), kind);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_form(input: &str) -> Sexpr {
        let (forms, errs) = may_i_sexpr::parse(input);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(forms.len(), 1);
        forms.into_iter().next().unwrap()
    }

    #[test]
    fn parses_minimal() {
        let p =
            parse_parser_form(&first_form(r#"(parser "find" (style single-dash-long))"#)).unwrap();
        assert_eq!(p.program, "find");
        assert_eq!(p.style_name, "single-dash-long");
        assert!(p.flags.is_empty());
        assert!(p.parameters.is_empty());
    }

    #[test]
    fn parses_flag_and_parameter() {
        let p = parse_parser_form(&first_form(
            r#"(parser "kubectl" (style gnu)
                 (flag "v")
                 (parameter ["n" "namespace"]))"#,
        ))
        .unwrap();
        assert_eq!(p.flags, vec![vec!["v".to_string()]]);
        assert_eq!(p.parameters.len(), 1);
        assert_eq!(
            p.parameters[0].names,
            vec!["n".to_string(), "namespace".to_string()]
        );
        assert_eq!(p.parameters[0].treatment, ParameterTreatment::None);
    }

    #[test]
    fn parses_authorise_treatment() {
        let p = parse_parser_form(&first_form(
            r#"(parser "bash" (style gnu) (parameter "c" (authorise)))"#,
        ))
        .unwrap();
        assert_eq!(p.parameters[0].treatment, ParameterTreatment::Authorise);
    }

    #[test]
    fn legacy_may_i_in_parameter_body_rejected() {
        let err = parse_parser_form(&first_form(
            r#"(parser "bash" (style gnu) (parameter "c" (may-i *)))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("(may-i …) is retired"));
    }

    #[test]
    fn rejects_missing_style_form() {
        let err = parse_parser_form(&first_form(r#"(parser "x" (flag "v"))"#)).unwrap_err();
        assert!(format!("{err}").contains("(style"));
    }

    #[test]
    fn rejects_duplicate_style_form() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (style legacy-bundle))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("more than once"));
    }

    #[test]
    fn rejects_unknown_body_item() {
        let err =
            parse_parser_form(&first_form(r#"(parser "x" (style gnu) (wat "v"))"#)).unwrap_err();
        assert!(format!("{err}").contains("wat"));
    }

    #[test]
    fn rejects_non_may_i_treatment() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (parameter "c" (regex ".+")))"#,
        ))
        .unwrap_err();
        assert!(
            format!("{err}").contains("unsupported parameter FORM"),
            "{err}"
        );
    }

    #[test]
    fn rejects_legacy_tail_form_with_migration_hint() {
        // The legacy `(tail (after …))` form is retired; the parser
        // rejects it at load time with a hint pointing at the new
        // `(flags MODE) (rest #cmd)` shape.
        let err = parse_parser_form(&first_form(
            r#"(parser "sudo" (style gnu) (tail (after :flags)))"#,
        ))
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("legacy"), "{msg}");
        assert!(msg.contains("retired"), "{msg}");
    }

    // ── parser-named-bindings: new-form body items ──────────────────

    #[test]
    fn parses_flags_posix() {
        let p =
            parse_parser_form(&first_form(r#"(parser "sudo" (style gnu) (flags posix))"#)).unwrap();
        assert_eq!(p.flags_mode, FlagsMode::Posix);
    }

    #[test]
    fn parses_flags_permute() {
        let p = parse_parser_form(&first_form(r#"(parser "git" (style gnu) (flags permute))"#))
            .unwrap();
        assert_eq!(p.flags_mode, FlagsMode::Permute);
    }

    #[test]
    fn parses_flags_until_single() {
        let p = parse_parser_form(&first_form(
            r#"(parser "mise" (style gnu) (flags (until "--")))"#,
        ))
        .unwrap();
        assert_eq!(p.flags_mode, FlagsMode::Until(vec!["--".to_string()]));
    }

    #[test]
    fn parses_flags_until_multi() {
        let p = parse_parser_form(&first_form(
            r#"(parser "nix" (style gnu) (flags (until "--command" "-c")))"#,
        ))
        .unwrap();
        assert_eq!(
            p.flags_mode,
            FlagsMode::Until(vec!["--command".to_string(), "-c".to_string()])
        );
    }

    #[test]
    fn rejects_duplicate_flags() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags posix) (flags permute))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("more than once"));
    }

    #[test]
    fn rejects_unknown_flags_mode() {
        let err = parse_parser_form(&first_form(r#"(parser "x" (style gnu) (flags strict))"#))
            .unwrap_err();
        assert!(format!("{err}").contains("unknown flag-scanning mode"));
    }

    #[test]
    fn rejects_flags_until_empty() {
        let err = parse_parser_form(&first_form(r#"(parser "x" (style gnu) (flags (until)))"#))
            .unwrap_err();
        assert!(format!("{err}").contains("at least one"));
    }

    #[test]
    fn parses_rest_binding() {
        let p = parse_parser_form(&first_form(
            r#"(parser "sudo" (style gnu) (flags posix) (rest #cmd))"#,
        ))
        .unwrap();
        assert_eq!(p.rest.as_ref().map(|b| b.as_str()), Some("cmd"));
    }

    #[test]
    fn rejects_rest_without_binding() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags posix) (rest))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("binding-name"));
    }

    #[test]
    fn rejects_rest_with_string() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags posix) (rest "cmd"))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("binding atom"));
    }

    #[test]
    fn rejects_duplicate_rest() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags posix) (rest #cmd) (rest #other))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("more than once"));
    }

    #[test]
    fn parses_positional_minimal() {
        let p = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags permute) (positional *))"#,
        ))
        .unwrap();
        assert_eq!(p.positionals.len(), 1);
        assert!(p.positionals[0].binding.is_none());
        assert_eq!(p.positionals[0].quantifier, Quantifier::One);
    }

    #[test]
    fn parses_positional_with_binding() {
        let p = parse_parser_form(&first_form(
            r#"(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))"#,
        ))
        .unwrap();
        assert_eq!(p.positionals.len(), 1);
        assert_eq!(
            p.positionals[0].binding.as_ref().map(|b| b.as_str()),
            Some("host")
        );
    }

    #[test]
    fn parses_positional_with_quantifier() {
        // PAT is required; QUANT comes after. `(positional #verb * *)`
        // is "any token, zero-or-more, bound to #verb".
        let p = parse_parser_form(&first_form(
            r#"(parser "direnv" (style posix) (flags posix) (positional #verb * *) (rest #cmd))"#,
        ))
        .unwrap();
        assert_eq!(p.positionals[0].quantifier, Quantifier::ZeroOrMore);
    }

    #[test]
    fn positional_default_quantifier_is_one() {
        let p = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags permute) (positional #host (regex "^h.*")))"#,
        ))
        .unwrap();
        assert_eq!(p.positionals[0].quantifier, Quantifier::One);
    }

    #[test]
    fn rejects_unknown_quantifier() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags permute) (positional * many))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("unknown quantifier"));
    }

    #[test]
    fn rejects_positional_duplicate_binding() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags permute)
                 (positional #a *) (positional #a +))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("declared more than once"));
    }

    #[test]
    fn parses_parameter_binding_form() {
        let p = parse_parser_form(&first_form(
            r#"(parser "bash" (style gnu) (flags permute) (parameter "c" #cmd))"#,
        ))
        .unwrap();
        assert_eq!(
            p.parameters[0].binding.as_ref().map(|b| b.as_str()),
            Some("cmd")
        );
        assert_eq!(p.parameters[0].treatment, ParameterTreatment::None);
    }

    #[test]
    fn parses_parameter_many_till_binding() {
        let p = parse_parser_form(&first_form(
            r#"(parser "find" (style gnu) (flags permute)
                 (parameter "exec" (many-till ";") #args))"#,
        ))
        .unwrap();
        assert_eq!(
            p.parameters[0].binding.as_ref().map(|b| b.as_str()),
            Some("args")
        );
        assert!(matches!(p.parameters[0].capture, Capture::ManyTill { .. }));
    }

    #[test]
    fn rejects_duplicate_binding_across_decls() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flags permute)
                 (parameter "c" #shared) (rest #shared))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("declared more than once"));
    }

    #[test]
    fn rejects_flag_param_conflict() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (flag "v") (parameter "v"))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("flag and parameter"));
    }
}

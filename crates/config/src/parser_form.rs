// Parser for `(parser PROGRAM (style STYLE) BODY…)` forms.
//
// BODY items are a uniform list of declaration forms:
//   (style STYLE)         — exactly one, required
//   (flag NAME)           — zero or more
//   (parameter NAME [F])  — zero or more
//
// NAME: a string (single spelling) or [short long] vector (two
// spellings). The optional FORM after a parameter name is a treatment
// declaration; in v2 only `(may-i *)` is accepted (the new
// `(authorise)` verb arrives in a later slice of the dsl-coherence
// change).

use may_i_core::ast::{Capture, ParameterDecl, ParameterTreatment, Parser, Provenance, Tail};
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
    let mut tail: Option<Tail> = None;
    let mut declared_names: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();

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
                let (treatment, capture) = if item_list.len() >= 3 {
                    parse_parameter_body(&item_list[2])?
                } else {
                    (ParameterTreatment::None, Capture::Single)
                };
                if item_list.len() > 3 {
                    return Err(RawError::new(
                        "parameter accepts at most one FORM after the name",
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
                });
            }
            "tail" => {
                if tail.is_some() {
                    return Err(RawError::new(
                        "parser body declares (tail …) more than once",
                        item.span(),
                    ));
                }
                tail = Some(parse_tail_decl(&item_list[1..], item.span())?);
            }
            other => {
                return Err(RawError::new(
                    format!("unknown parser body item: {other}"),
                    item.span(),
                )
                .with_help(
                    "body items: (style …), (flag NAME), (parameter NAME [FORM]), (tail (after …))",
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

    Ok(Parser {
        program,
        style_name,
        flags,
        parameters,
        tail,
        span: sexpr.span(),
        provenance: Provenance::PrimaryConfig,
    })
}

/// Parse the body of a `(tail …)` declaration in a parser body.
///
/// Recognised shapes:
/// - `(tail (after :flags))` — wrapper-style boundary at end of outer flags
/// - `(tail (after "TOK"))` — explicit token boundary (e.g. `--`)
fn parse_tail_decl(args: &[Sexpr], span: may_i_core::Span) -> Result<Tail, RawError> {
    if args.len() != 1 {
        return Err(
            RawError::new("(tail …) takes exactly one (after VALUE) form", span)
                .with_help("(tail (after :flags)) or (tail (after \"--\"))"),
        );
    }
    let after_list = args[0]
        .as_list()
        .ok_or_else(|| RawError::new("(tail …) body must be (after VALUE)", args[0].span()))?;
    if after_list.first().and_then(Sexpr::as_atom) != Some("after") {
        return Err(RawError::new(
            "(tail …) body must start with `after`",
            args[0].span(),
        ));
    }
    if after_list.len() != 2 {
        return Err(RawError::new(
            "(after …) takes exactly one VALUE",
            args[0].span(),
        ));
    }
    let value = &after_list[1];
    if let Some(s) = value.as_str() {
        return Ok(Tail::AfterToken(s.to_string()));
    }
    if let Some(atom) = value.as_atom() {
        match atom {
            ":flags" => return Ok(Tail::AfterFlags),
            other if other.starts_with(':') => {
                return Err(RawError::new(
                    format!("unrecognised tail keyword: {other}"),
                    value.span(),
                )
                .with_help("only `:flags` is recognised"));
            }
            _ => {}
        }
    }
    Err(RawError::new(
        "(after VALUE) value must be `:flags` or a string literal token",
        value.span(),
    ))
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
/// - `(authorise)` / `(may-i *)` — value treatment is [`ParameterTreatment::MayI`].
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
            Ok((ParameterTreatment::MayI, Capture::Single))
        }
        "may-i" => {
            if list.len() != 2 {
                return Err(RawError::new(
                    "(may-i *) is the only legacy FORM accepted; prefer (authorise)",
                    sexpr.span(),
                ));
            }
            let star = list[1]
                .as_atom()
                .ok_or_else(|| RawError::new("expected `*` after may-i", list[1].span()))?;
            if star != "*" {
                return Err(RawError::new(
                    format!("expected `*` after may-i, got `{star}`"),
                    list[1].span(),
                ));
            }
            Ok((ParameterTreatment::MayI, Capture::Single))
        }
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
                .with_help("use (authorise), (may-i *), or (many-till PAT)"),
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
    fn parses_may_i_treatment() {
        let p = parse_parser_form(&first_form(
            r#"(parser "bash" (style gnu) (parameter "c" (may-i *)))"#,
        ))
        .unwrap();
        assert_eq!(p.parameters[0].treatment, ParameterTreatment::MayI);
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
    fn parses_tail_after_flags() {
        let p = parse_parser_form(&first_form(
            r#"(parser "sudo" (style gnu) (tail (after :flags)))"#,
        ))
        .unwrap();
        assert_eq!(p.tail, Some(Tail::AfterFlags));
    }

    #[test]
    fn parses_tail_after_token() {
        let p = parse_parser_form(&first_form(
            r#"(parser "mise" (style gnu) (tail (after "--")))"#,
        ))
        .unwrap();
        assert_eq!(p.tail, Some(Tail::AfterToken("--".to_string())));
    }

    #[test]
    fn rejects_duplicate_tail() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (tail (after :flags)) (tail (after "--")))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("more than once"));
    }

    #[test]
    fn rejects_unknown_tail_keyword() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" (style gnu) (tail (after :wibble)))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains(":wibble"));
    }

    #[test]
    fn rejects_tail_without_after() {
        let err = parse_parser_form(&first_form(r#"(parser "x" (style gnu) (tail :flags))"#))
            .unwrap_err();
        assert!(format!("{err}").contains("(after VALUE)"));
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

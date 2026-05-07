// Parser for `(parser PROGRAM :style STYLE BODY…)` forms.
//
// BODY items:
//   (flag NAME)
//   (parameter NAME [FORM])
//
// NAME: a string (single spelling) or [short long] vector (two
// spellings). FORM in v1: omitted ⇒ ParameterTreatment::None;
// `(may-i *)` ⇒ ParameterTreatment::MayI; anything else rejected.

use may_i_core::ast::{ParameterDecl, ParameterTreatment, Parser, Provenance};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a top-level `(parser PROGRAM :style STYLE BODY…)` form.
pub fn parse_parser_form(sexpr: &Sexpr) -> Result<Parser, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("parser form must be a list", sexpr.span()))?;

    if list.len() < 4 {
        return Err(RawError::new(
            "parser requires a program, :style, and a style name",
            sexpr.span(),
        )
        .with_help("(parser \"git\" :style gnu (flag \"v\") …)"));
    }

    let program = list[1]
        .as_atom_or_str()
        .ok_or_else(|| RawError::new("parser program must be a string", list[1].span()))?
        .to_string();

    let style_kw = list[2]
        .as_atom()
        .ok_or_else(|| RawError::new("expected :style keyword", list[2].span()))?;
    if style_kw != ":style" {
        return Err(RawError::new(
            format!("expected `:style`, got `{style_kw}`"),
            list[2].span(),
        ));
    }

    let style_name = list[3]
        .as_atom()
        .ok_or_else(|| RawError::new("style name must be an atom", list[3].span()))?
        .to_string();

    let mut flags: Vec<Vec<String>> = Vec::new();
    let mut parameters: Vec<ParameterDecl> = Vec::new();
    let mut declared_names: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();

    for item in &list[4..] {
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
                let treatment = if item_list.len() >= 3 {
                    parse_treatment(&item_list[2])?
                } else {
                    ParameterTreatment::None
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
                parameters.push(ParameterDecl { names, treatment });
            }
            other => {
                return Err(RawError::new(
                    format!("unknown parser body item: {other}"),
                    item.span(),
                )
                .with_help("body items: (flag NAME) or (parameter NAME [FORM])"));
            }
        }
    }

    Ok(Parser {
        program,
        style_name,
        flags,
        parameters,
        span: sexpr.span(),
        provenance: Provenance::PrimaryConfig,
    })
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

/// Parse the optional FORM after `(parameter NAME …)`. Only `(may-i *)`
/// is accepted in v1.
fn parse_treatment(sexpr: &Sexpr) -> Result<ParameterTreatment, RawError> {
    let list = sexpr.as_list().ok_or_else(|| {
        RawError::new(
            "parameter FORM must be a list, e.g. (may-i *)",
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
        "may-i" => {
            if list.len() != 2 {
                return Err(RawError::new(
                    "(may-i *) is the only FORM accepted in v1",
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
            Ok(ParameterTreatment::MayI)
        }
        other => Err(
            RawError::new(format!("unsupported parameter FORM: {other}"), sexpr.span())
                .with_help("only (may-i *) is accepted in v1"),
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
            parse_parser_form(&first_form(r#"(parser "find" :style single-dash-long)"#)).unwrap();
        assert_eq!(p.program, "find");
        assert_eq!(p.style_name, "single-dash-long");
        assert!(p.flags.is_empty());
        assert!(p.parameters.is_empty());
    }

    #[test]
    fn parses_flag_and_parameter() {
        let p = parse_parser_form(&first_form(
            r#"(parser "kubectl" :style gnu
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
            r#"(parser "bash" :style gnu (parameter "c" (may-i *)))"#,
        ))
        .unwrap();
        assert_eq!(p.parameters[0].treatment, ParameterTreatment::MayI);
    }

    #[test]
    fn rejects_missing_style_keyword() {
        let err = parse_parser_form(&first_form(r#"(parser "x" gnu (flag "v"))"#)).unwrap_err();
        assert!(format!("{err}").contains(":style"));
    }

    #[test]
    fn rejects_unknown_body_item() {
        let err =
            parse_parser_form(&first_form(r#"(parser "x" :style gnu (wat "v"))"#)).unwrap_err();
        assert!(format!("{err}").contains("wat"));
    }

    #[test]
    fn rejects_non_may_i_treatment() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" :style gnu (parameter "c" (regex ".+")))"#,
        ))
        .unwrap_err();
        assert!(
            format!("{err}").contains("unsupported parameter FORM"),
            "{err}"
        );
    }

    #[test]
    fn rejects_flag_param_conflict() {
        let err = parse_parser_form(&first_form(
            r#"(parser "x" :style gnu (flag "v") (parameter "v"))"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("flag and parameter"));
    }
}

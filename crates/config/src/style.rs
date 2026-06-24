// Parser for `(define-arg-style NAME (overrides …) (long-prefix …) …)`.
//
// The body is a uniform list of attribute forms:
//
//   (overrides NAME)
//   (long-prefix STRING)
//   (short-prefix STRING)
//   (separators STRING …)        — variadic
//   (combined-shorts BOOL)
//   (first-token-bundle BOOL)
//   (pun :allow|:error)

use may_i_core::ast::{Provenance, PunPolicy, StyleSpec};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a top-level `(define-arg-style NAME ATTR…)` form into a `StyleSpec`.
pub(crate) fn parse_style_definition(sexpr: &Sexpr) -> Result<StyleSpec, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("define-arg-style must be a list", sexpr.span()))?;

    if list.len() < 2 {
        return Err(
            RawError::new("define-arg-style requires a name", sexpr.span())
                .with_help("(define-arg-style NAME (long-prefix \"--\") …)"),
        );
    }

    let name = list[1]
        .as_atom()
        .ok_or_else(|| RawError::new("define-arg-style name must be an atom", list[1].span()))?
        .to_string();

    let mut spec = StyleSpec {
        name: name.clone(),
        overrides: None,
        long_prefix: None,
        short_prefix: None,
        separators: None,
        combined_shorts: None,
        first_token_bundle: None,
        pun: None,
        span: sexpr.span(),
        provenance: Provenance::PrimaryConfig,
    };

    let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

    for attr in &list[2..] {
        let attr_list = attr.as_list().ok_or_else(|| {
            RawError::new("define-arg-style body items must be lists", attr.span())
        })?;
        if attr_list.is_empty() {
            return Err(RawError::new(
                "empty define-arg-style attribute",
                attr.span(),
            ));
        }
        let tag = attr_list[0].as_atom().ok_or_else(|| {
            RawError::new(
                "define-arg-style attribute tag must be an atom",
                attr_list[0].span(),
            )
        })?;

        let attr_name: &'static str = match tag {
            "overrides" => "overrides",
            "long-prefix" => "long-prefix",
            "short-prefix" => "short-prefix",
            "separators" => "separators",
            "combined-shorts" => "combined-shorts",
            "first-token-bundle" => "first-token-bundle",
            "pun" => "pun",
            other => {
                return Err(RawError::new(
                    format!("unknown define-arg-style attribute: {other}"),
                    attr.span(),
                )
                .with_help(
                    "valid attributes: (overrides NAME) (long-prefix STRING) \
                     (short-prefix STRING) (separators STRING …) \
                     (combined-shorts BOOL) (first-token-bundle BOOL) (pun :allow|:error)",
                ));
            }
        };

        if !seen.insert(attr_name) {
            crate::record_advisory(format!(
                "warning: duplicate (define-arg-style {name}) attribute `{attr_name}` — last declaration wins"
            ));
        }

        match attr_name {
            "overrides" => {
                spec.overrides = Some(read_single_atom(attr_list, attr.span(), "overrides")?);
            }
            "long-prefix" => {
                spec.long_prefix = Some(read_single_string(attr_list, attr.span(), "long-prefix")?);
            }
            "short-prefix" => {
                spec.short_prefix =
                    Some(read_single_string(attr_list, attr.span(), "short-prefix")?);
            }
            "separators" => {
                spec.separators =
                    Some(read_variadic_strings(attr_list, attr.span(), "separators")?);
            }
            "combined-shorts" => {
                spec.combined_shorts =
                    Some(read_single_bool(attr_list, attr.span(), "combined-shorts")?);
            }
            "first-token-bundle" => {
                spec.first_token_bundle = Some(read_single_bool(
                    attr_list,
                    attr.span(),
                    "first-token-bundle",
                )?);
            }
            "pun" => {
                spec.pun = Some(read_pun_attr(attr_list, attr.span())?);
            }
            _ => unreachable!(),
        }
    }

    Ok(spec)
}

fn read_single_atom(
    list: &[Sexpr],
    span: may_i_core::Span,
    name: &str,
) -> Result<String, RawError> {
    if list.len() != 2 {
        return Err(RawError::new(
            format!("({name} …) takes exactly one atom"),
            span,
        ));
    }
    list[1]
        .as_atom()
        .map(str::to_string)
        .ok_or_else(|| RawError::new(format!("({name} …) value must be an atom"), list[1].span()))
}

fn read_single_string(
    list: &[Sexpr],
    span: may_i_core::Span,
    name: &str,
) -> Result<String, RawError> {
    if list.len() != 2 {
        return Err(RawError::new(
            format!("({name} …) takes exactly one string"),
            span,
        ));
    }
    list[1]
        .as_atom_or_str()
        .map(str::to_string)
        .ok_or_else(|| RawError::new(format!("({name} …) value must be a string"), list[1].span()))
}

fn read_variadic_strings(
    list: &[Sexpr],
    span: may_i_core::Span,
    name: &str,
) -> Result<Vec<String>, RawError> {
    if list.len() < 2 {
        return Err(RawError::new(
            format!("({name} …) requires at least one value"),
            span,
        ));
    }
    let mut out = Vec::with_capacity(list.len() - 1);
    for item in &list[1..] {
        let s = item.as_atom_or_str().ok_or_else(|| {
            RawError::new(format!("({name} …) values must be strings"), item.span())
        })?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn read_single_bool(list: &[Sexpr], span: may_i_core::Span, name: &str) -> Result<bool, RawError> {
    if list.len() != 2 {
        return Err(RawError::new(
            format!("({name} …) takes exactly one boolean (`t` or `nil`)"),
            span,
        ));
    }
    let atom = list[1].as_atom().ok_or_else(|| {
        RawError::new(
            format!("({name} …) value must be `t` or `nil`"),
            list[1].span(),
        )
    })?;
    match atom {
        "t" | "true" => Ok(true),
        "nil" | "false" => Ok(false),
        other => Err(RawError::new(
            format!("({name} …) value must be `t` or `nil`, got `{other}`"),
            list[1].span(),
        )),
    }
}

fn read_pun_attr(list: &[Sexpr], span: may_i_core::Span) -> Result<PunPolicy, RawError> {
    if list.len() != 2 {
        return Err(RawError::new(
            "(pun …) takes exactly one keyword (:allow or :error)",
            span,
        ));
    }
    let atom = list[1]
        .as_atom()
        .ok_or_else(|| RawError::new("(pun …) value must be a keyword", list[1].span()))?;
    PunPolicy::from_keyword(atom).ok_or_else(|| {
        RawError::new(
            format!("(pun …) value must be :allow or :error, got `{atom}`"),
            list[1].span(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::StyleRegistry;

    fn first_form(input: &str) -> Sexpr {
        let (forms, errs) = may_i_sexpr::parse(input);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(forms.len(), 1);
        forms.into_iter().next().unwrap()
    }

    #[test]
    fn parses_full_gnu_style() {
        let form = first_form(
            r#"(define-arg-style gnu
                 (long-prefix "--")
                 (short-prefix "-")
                 (separators " " "=")
                 (combined-shorts t)
                 (pun :allow))"#,
        );
        let spec = parse_style_definition(&form).unwrap();
        assert_eq!(spec.name, "gnu");
        assert_eq!(spec.long_prefix.as_deref(), Some("--"));
        assert_eq!(spec.short_prefix.as_deref(), Some("-"));
        assert_eq!(
            spec.separators.as_deref(),
            Some([" ".to_string(), "=".to_string()].as_slice())
        );
        assert_eq!(spec.combined_shorts, Some(true));
        assert_eq!(spec.pun, Some(PunPolicy::Allow));
        assert!(spec.overrides.is_none());
    }

    #[test]
    fn parses_overrides() {
        let form = first_form(
            r#"(define-arg-style legacy-bundle (overrides gnu) (first-token-bundle t))"#,
        );
        let spec = parse_style_definition(&form).unwrap();
        assert_eq!(spec.overrides.as_deref(), Some("gnu"));
        assert_eq!(spec.first_token_bundle, Some(true));
    }

    #[test]
    fn rejects_unknown_attribute() {
        let form = first_form(r#"(define-arg-style bad (wibble "x"))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains("wibble"), "{err}");
    }

    #[test]
    fn rejects_missing_value() {
        let form = first_form(r#"(define-arg-style x (long-prefix))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains("long-prefix"), "{err}");
    }

    #[test]
    fn rejects_bad_pun() {
        let form = first_form(r#"(define-arg-style x (pun :wat))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains(":allow"), "{err}");
    }

    #[test]
    fn registry_resolves_simple_style() {
        let form = first_form(
            r#"(define-arg-style mine (long-prefix "--") (short-prefix "-") (pun :error))"#,
        );
        let mut reg = StyleRegistry::new();
        reg.push(parse_style_definition(&form).unwrap());
        let style = reg.resolve("mine").unwrap();
        assert_eq!(style.long_prefix(), "--");
        assert_eq!(style.pun(), PunPolicy::Error);
    }

    #[test]
    fn registry_overrides_replaces_list_keys() {
        let mut reg = StyleRegistry::new();
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style gnu (separators " " "="))"#,
            ))
            .unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style java (overrides gnu) (separators " " "=" ":"))"#,
            ))
            .unwrap(),
        );
        let java = reg.resolve("java").unwrap();
        assert_eq!(java.separators(), &[" ", "=", ":"]);
    }

    #[test]
    fn registry_unknown_base_errors() {
        let mut reg = StyleRegistry::new();
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style derived (overrides nope))"#,
            ))
            .unwrap(),
        );
        let err = reg.resolve("derived").unwrap_err();
        assert!(format!("{err}").contains("nope"), "{err}");
    }

    #[test]
    fn registry_cycle_errors() {
        let mut reg = StyleRegistry::new();
        reg.push(
            parse_style_definition(&first_form(r#"(define-arg-style a (overrides b))"#)).unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(r#"(define-arg-style b (overrides a))"#)).unwrap(),
        );
        let err = reg.resolve("a").unwrap_err();
        assert!(format!("{err}").contains("cycle"), "{err}");
    }

    #[test]
    fn registry_last_wins_on_duplicate() {
        let mut reg = StyleRegistry::new();
        reg.push(
            parse_style_definition(&first_form(r#"(define-arg-style mine (long-prefix "--"))"#))
                .unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(r#"(define-arg-style mine (long-prefix "++"))"#))
                .unwrap(),
        );
        let style = reg.resolve("mine").unwrap();
        assert_eq!(style.long_prefix(), "++");
    }
}

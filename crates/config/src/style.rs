// Parser for `(define-arg-style NAME (PLIST))` and the inner style PLIST.
//
// Kept separate from the predicate-binding `(define …)` form for now (see
// design discussion in proposal.md). The PLIST grammar is:
//
//   :long-prefix STRING
//   :short-prefix STRING
//   :separators (STRING …)
//   :combined-shorts BOOL
//   :first-token-bundle BOOL
//   :pun (:allow | :error)
//   :overrides NAME

use may_i_core::ast::{Provenance, PunPolicy, StyleSpec};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a top-level `(define-arg-style NAME (PLIST))` form into a
/// `StyleSpec`. Caller assigns `Provenance` if needed (defaults to
/// `PrimaryConfig`).
pub fn parse_style_definition(sexpr: &Sexpr) -> Result<StyleSpec, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("define-arg-style must be a list", sexpr.span()))?;

    if list.len() != 3 {
        return Err(RawError::new(
            "define-arg-style requires a name and a property-list body",
            sexpr.span(),
        )
        .with_help("(define-arg-style NAME (:long-prefix \"--\" …))"));
    }

    let name = list[1]
        .as_atom()
        .ok_or_else(|| RawError::new("define-arg-style name must be an atom", list[1].span()))?
        .to_string();

    let plist = list[2].as_list().ok_or_else(|| {
        RawError::new(
            "define-arg-style body must be a property-list",
            list[2].span(),
        )
    })?;

    parse_style_plist(&name, plist, sexpr.span())
}

/// Parse a PLIST body into a `StyleSpec`. `name` and `span` come from the
/// outer form. Pure: no provenance assigned.
fn parse_style_plist(
    name: &str,
    plist: &[Sexpr],
    outer_span: may_i_core::Span,
) -> Result<StyleSpec, RawError> {
    let mut spec = StyleSpec {
        name: name.to_string(),
        overrides: None,
        long_prefix: None,
        short_prefix: None,
        separators: None,
        combined_shorts: None,
        first_token_bundle: None,
        pun: None,
        span: outer_span,
        provenance: Provenance::PrimaryConfig,
    };

    let mut i = 0;
    while i < plist.len() {
        let key_atom = plist[i].as_atom().ok_or_else(|| {
            RawError::new(
                "style PLIST keys must be keywords like :long-prefix",
                plist[i].span(),
            )
        })?;
        if !key_atom.starts_with(':') {
            return Err(RawError::new(
                format!("style PLIST key must be a keyword, got `{key_atom}`"),
                plist[i].span(),
            ));
        }
        if i + 1 >= plist.len() {
            return Err(RawError::new(
                format!("missing value for style PLIST key `{key_atom}`"),
                plist[i].span(),
            ));
        }
        let value = &plist[i + 1];

        match key_atom {
            ":long-prefix" => spec.long_prefix = Some(read_string(value, key_atom)?),
            ":short-prefix" => spec.short_prefix = Some(read_string(value, key_atom)?),
            ":separators" => spec.separators = Some(read_string_list(value, key_atom)?),
            ":combined-shorts" => spec.combined_shorts = Some(read_bool(value, key_atom)?),
            ":first-token-bundle" => spec.first_token_bundle = Some(read_bool(value, key_atom)?),
            ":pun" => spec.pun = Some(read_pun(value)?),
            ":overrides" => spec.overrides = Some(read_atom(value, key_atom)?),
            other => {
                return Err(RawError::new(
                    format!("unknown style PLIST key: {other}"),
                    plist[i].span(),
                )
                .with_help(
                    "valid keys: :long-prefix :short-prefix :separators \
                     :combined-shorts :first-token-bundle :pun :overrides",
                ));
            }
        }

        i += 2;
    }

    Ok(spec)
}

fn read_string(sexpr: &Sexpr, key: &str) -> Result<String, RawError> {
    sexpr
        .as_atom_or_str()
        .map(str::to_string)
        .ok_or_else(|| RawError::new(format!("{key} value must be a string"), sexpr.span()))
}

fn read_atom(sexpr: &Sexpr, key: &str) -> Result<String, RawError> {
    sexpr
        .as_atom()
        .map(str::to_string)
        .ok_or_else(|| RawError::new(format!("{key} value must be an atom"), sexpr.span()))
}

fn read_string_list(sexpr: &Sexpr, key: &str) -> Result<Vec<String>, RawError> {
    let list = sexpr.as_list().ok_or_else(|| {
        RawError::new(
            format!("{key} value must be a list of strings"),
            sexpr.span(),
        )
    })?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let s = item.as_atom_or_str().ok_or_else(|| {
            RawError::new(format!("{key} list elements must be strings"), item.span())
        })?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn read_bool(sexpr: &Sexpr, key: &str) -> Result<bool, RawError> {
    let atom = sexpr
        .as_atom()
        .ok_or_else(|| RawError::new(format!("{key} value must be `t` or `nil`"), sexpr.span()))?;
    match atom {
        "t" | "true" => Ok(true),
        "nil" | "false" => Ok(false),
        other => Err(RawError::new(
            format!("{key} value must be `t` or `nil`, got `{other}`"),
            sexpr.span(),
        )),
    }
}

fn read_pun(sexpr: &Sexpr) -> Result<PunPolicy, RawError> {
    let atom = sexpr.as_atom().ok_or_else(|| {
        RawError::new(
            ":pun value must be a keyword (:allow or :error)",
            sexpr.span(),
        )
    })?;
    PunPolicy::from_keyword(atom).ok_or_else(|| {
        RawError::new(
            format!(":pun value must be :allow or :error, got `{atom}`"),
            sexpr.span(),
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
                 (:long-prefix "--"
                  :short-prefix "-"
                  :separators (" " "=")
                  :combined-shorts t
                  :pun :allow))"#,
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
            r#"(define-arg-style legacy-bundle (:overrides gnu :first-token-bundle t))"#,
        );
        let spec = parse_style_definition(&form).unwrap();
        assert_eq!(spec.overrides.as_deref(), Some("gnu"));
        assert_eq!(spec.first_token_bundle, Some(true));
    }

    #[test]
    fn rejects_unknown_key() {
        let form = first_form(r#"(define-arg-style bad (:wibble "x"))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains(":wibble"), "{err}");
    }

    #[test]
    fn rejects_missing_value() {
        let form = first_form(r#"(define-arg-style x (:long-prefix))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains("missing value"), "{err}");
    }

    #[test]
    fn rejects_non_keyword_key() {
        let form = first_form(r#"(define-arg-style x (long-prefix "--"))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains("must be a keyword"), "{err}");
    }

    #[test]
    fn rejects_bad_pun() {
        let form = first_form(r#"(define-arg-style x (:pun :wat))"#);
        let err = parse_style_definition(&form).unwrap_err();
        assert!(format!("{err}").contains(":allow"), "{err}");
    }

    #[test]
    fn registry_resolves_simple_style() {
        let form = first_form(
            r#"(define-arg-style mine
                 (:long-prefix "--" :short-prefix "-" :pun :error))"#,
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
                r#"(define-arg-style gnu (:separators (" " "=")))"#,
            ))
            .unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style java (:overrides gnu :separators (" " "=" ":")))"#,
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
                r#"(define-arg-style derived (:overrides nope))"#,
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
            parse_style_definition(&first_form(r#"(define-arg-style a (:overrides b))"#)).unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(r#"(define-arg-style b (:overrides a))"#)).unwrap(),
        );
        let err = reg.resolve("a").unwrap_err();
        assert!(format!("{err}").contains("cycle"), "{err}");
    }

    #[test]
    fn registry_last_wins_on_duplicate() {
        let mut reg = StyleRegistry::new();
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style mine (:long-prefix "--"))"#,
            ))
            .unwrap(),
        );
        reg.push(
            parse_style_definition(&first_form(
                r#"(define-arg-style mine (:long-prefix "++"))"#,
            ))
            .unwrap(),
        );
        let style = reg.resolve("mine").unwrap();
        assert_eq!(style.long_prefix(), "++");
    }
}

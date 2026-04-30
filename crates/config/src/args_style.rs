// Parser for `(args-style PROGRAM :PROFILE [:flags-with-values (FLAG ...)])`.

use may_i_core::ast::{ArgsStyle, Convention, Profile, Provenance};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a top-level `(args-style ...)` form.
///
/// Syntax: `(args-style PROGRAM :PROFILE [:flags-with-values (FLAG ...)])`
pub fn parse_args_style(sexpr: &Sexpr) -> Result<ArgsStyle, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("args-style must be a list", sexpr.span()))?;

    if list.len() < 3 {
        return Err(RawError::new(
            "args-style requires a program name and a profile keyword",
            sexpr.span(),
        )
        .with_help("(args-style PROGRAM :PROFILE [:flags-with-values (...)])"));
    }

    let program = list[1]
        .as_atom_or_str()
        .ok_or_else(|| RawError::new("args-style program must be a string", list[1].span()))?
        .to_string();

    let profile_kw = list[2].as_atom().ok_or_else(|| {
        RawError::new(
            "args-style profile must be a keyword like :gnu or :single-dash-long",
            list[2].span(),
        )
    })?;

    let profile = Profile::from_keyword(profile_kw).ok_or_else(|| {
        RawError::new(
            format!("unknown args-style profile: {profile_kw}"),
            list[2].span(),
        )
        .with_help("valid profiles: :gnu, :single-dash-long, :legacy-bundle, :key-value")
    })?;

    let mut flags_with_values: Vec<String> = Vec::new();

    let mut i = 3;
    while i < list.len() {
        let kw = list[i].as_atom().ok_or_else(|| {
            RawError::new(
                "args-style override must be a keyword like :flags-with-values",
                list[i].span(),
            )
        })?;

        match kw {
            ":flags-with-values" => {
                if i + 1 >= list.len() {
                    return Err(RawError::new(
                        ":flags-with-values requires a list of flag strings",
                        list[i].span(),
                    ));
                }
                let inner = list[i + 1].as_list().ok_or_else(|| {
                    RawError::new(
                        ":flags-with-values requires a list of flag strings",
                        list[i + 1].span(),
                    )
                    .with_help(
                        "(args-style \"kubectl\" :gnu :flags-with-values (\"-n\" \"--namespace\"))",
                    )
                })?;
                for flag in inner {
                    let s = flag.as_atom_or_str().ok_or_else(|| {
                        RawError::new(":flags-with-values entry must be a string", flag.span())
                    })?;
                    flags_with_values.push(s.to_string());
                }
                i += 2;
            }
            other => {
                return Err(RawError::new(
                    format!("unknown args-style override: {other}"),
                    list[i].span(),
                )
                .with_help("supported overrides: :flags-with-values"));
            }
        }
    }

    Ok(ArgsStyle {
        program,
        convention: Convention {
            profile,
            flags_with_values,
        },
        span: sexpr.span(),
        provenance: Provenance::PrimaryConfig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_sexpr::parse;

    fn first_form(s: &str) -> Sexpr {
        let (forms, errs) = parse(s);
        assert!(errs.is_empty(), "parse errors: {errs:?}");
        forms.into_iter().next().unwrap()
    }

    #[test]
    fn parses_simple_profile() {
        let form = first_form(r#"(args-style "find" :single-dash-long)"#);
        let style = parse_args_style(&form).unwrap();
        assert_eq!(style.program, "find");
        assert_eq!(style.convention.profile, Profile::SingleDashLong);
        assert!(style.convention.flags_with_values.is_empty());
    }

    #[test]
    fn parses_with_flags_with_values() {
        let form =
            first_form(r#"(args-style "kubectl" :gnu :flags-with-values ("-n" "--namespace"))"#);
        let style = parse_args_style(&form).unwrap();
        assert_eq!(style.convention.profile, Profile::Gnu);
        assert_eq!(
            style.convention.flags_with_values,
            vec!["-n".to_string(), "--namespace".to_string()]
        );
    }

    #[test]
    fn rejects_unknown_profile() {
        let form = first_form(r#"(args-style "x" :weird)"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("unknown args-style profile"));
    }

    #[test]
    fn rejects_missing_profile() {
        let form = first_form(r#"(args-style "x")"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("requires a program name"));
    }

    #[test]
    fn rejects_non_string_program() {
        let form = first_form(r#"(args-style () :gnu)"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("program must be a string"));
    }

    #[test]
    fn rejects_unknown_override() {
        let form = first_form(r#"(args-style "x" :gnu :weird (foo))"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("unknown args-style override"));
    }

    #[test]
    fn rejects_flags_with_values_missing_list() {
        let form = first_form(r#"(args-style "x" :gnu :flags-with-values)"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("list of flag strings"));
    }

    #[test]
    fn rejects_flags_with_values_non_list() {
        let form = first_form(r#"(args-style "x" :gnu :flags-with-values :foo)"#);
        let err = parse_args_style(&form).expect_err("expected error");
        assert!(format!("{err}").contains("list of flag strings"));
    }
}

// Prelude `(define-arg-style …)` and `(parser …)` declarations, auto-loaded
// into every parsed config so user `(overrides gnu)` resolves out of the
// box and common wrapper tools (sudo, xargs, env, …) come pre-declared.
//
// User declarations come after prelude entries, so user
// `(define-arg-style gnu …)` or `(parser "sudo" …)` shadows the prelude
// (last-wins per the relevant registry).

use may_i_core::ast::{Parser, StyleSpec};

const PRELUDE_SOURCE: &str = r#"
(define-arg-style gnu
  (long-prefix "--")
  (short-prefix "-")
  (separators " " "=")
  (combined-shorts t)
  (pun :allow))

(define-arg-style single-dash-long
  (long-prefix "-")
  (short-prefix "-")
  (separators " " "=")
  (combined-shorts nil)
  (pun :allow))

(define-arg-style legacy-bundle
  (overrides gnu)
  (first-token-bundle t))

(define-arg-style key-value
  (long-prefix "")
  (short-prefix "")
  (separators "=")
  (combined-shorts nil)
  (pun :error))
"#;

/// Prelude `(parser …)` declarations for the common wrapper tools. Each
/// declares a `(tail (after …))` boundary so the engine's outer/tail
/// split runs without the user having to redeclare the wrapper shape.
///
/// `find` is intentionally absent until `(many-till …)` lands in §12;
/// it cannot be modelled correctly without multi-token capture.
const PRELUDE_PARSER_SOURCE: &str = r#"
(parser "sudo"    (style gnu) (tail (after :flags)))
(parser "env"     (style gnu) (tail (after :flags)))
(parser "timeout" (style gnu) (tail (after :flags)))
(parser "time"    (style gnu) (tail (after :flags)))
(parser "su"      (style gnu) (tail (after :flags)))
(parser "ionice"  (style gnu) (tail (after :flags)))
(parser "chrt"    (style gnu) (tail (after :flags)))
(parser "xargs"
  (style gnu)
  (parameter ["n" "I" "L" "P" "d"])
  (flag ["0" "r"])
  (tail (after :flags)))
(parser "nice"    (style gnu) (parameter "n") (tail (after :flags)))
(parser "watch"
  (style gnu)
  (parameter ["n" "interval"])
  (tail (after :flags)))
(parser "mise"    (style gnu) (tail (after "--")))
"#;

/// Parse the prelude source into `StyleSpec`s. Panics if the prelude is
/// malformed — that's a build-time programming error, not user input.
pub fn prelude_style_specs() -> Vec<StyleSpec> {
    let (forms, errs) = may_i_sexpr::parse(PRELUDE_SOURCE);
    assert!(errs.is_empty(), "prelude parse errors: {errs:?}");

    let mut specs = Vec::with_capacity(forms.len());
    for form in &forms {
        let spec = crate::style::parse_style_definition(form)
            .expect("prelude define-arg-style failed to parse");
        specs.push(spec);
    }
    specs
}

/// Parse the prelude wrapper-parser source into `Parser`s. Panics if
/// malformed — build-time programming error, not user input.
pub fn prelude_parsers() -> Vec<Parser> {
    let (forms, errs) = may_i_sexpr::parse(PRELUDE_PARSER_SOURCE);
    assert!(errs.is_empty(), "prelude parser parse errors: {errs:?}");

    let mut parsers = Vec::with_capacity(forms.len());
    for form in &forms {
        let mut parser = crate::parser_form::parse_parser_form(form)
            .expect("prelude parser declaration failed to parse");
        parser.provenance = may_i_core::ast::Provenance::Prelude;
        parsers.push(parser);
    }
    parsers
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{PunPolicy, StyleRegistry};

    fn registry_from_prelude() -> StyleRegistry {
        let mut reg = StyleRegistry::new();
        for spec in prelude_style_specs() {
            reg.push(spec);
        }
        reg
    }

    #[test]
    fn gnu_resolves() {
        let reg = registry_from_prelude();
        let g = reg.resolve("gnu").unwrap();
        assert_eq!(g.long_prefix(), "--");
        assert_eq!(g.short_prefix(), "-");
        assert_eq!(g.separators(), &[" ", "="]);
        assert!(g.combined_shorts());
        assert!(!g.first_token_bundle());
        assert_eq!(g.pun(), PunPolicy::Allow);
    }

    #[test]
    fn single_dash_long_resolves() {
        let reg = registry_from_prelude();
        let s = reg.resolve("single-dash-long").unwrap();
        assert_eq!(s.long_prefix(), "-");
        assert!(!s.combined_shorts());
    }

    #[test]
    fn legacy_bundle_inherits_gnu() {
        let reg = registry_from_prelude();
        let lb = reg.resolve("legacy-bundle").unwrap();
        assert_eq!(lb.long_prefix(), "--");
        assert!(lb.combined_shorts());
        assert!(lb.first_token_bundle());
    }

    #[test]
    fn key_value_resolves() {
        let reg = registry_from_prelude();
        let kv = reg.resolve("key-value").unwrap();
        assert_eq!(kv.long_prefix(), "");
        assert_eq!(kv.separators(), &["="]);
        assert_eq!(kv.pun(), PunPolicy::Error);
    }

    #[test]
    fn user_define_shadows_prelude() {
        // Simulate the order that parse_config uses: prelude first, then user.
        let mut reg = registry_from_prelude();
        let form = {
            let (forms, errs) = may_i_sexpr::parse(r#"(define-arg-style gnu (long-prefix "++"))"#);
            assert!(errs.is_empty());
            forms.into_iter().next().unwrap()
        };
        reg.push(crate::style::parse_style_definition(&form).unwrap());
        let g = reg.resolve("gnu").unwrap();
        assert_eq!(g.long_prefix(), "++");
    }

    #[test]
    fn user_overrides_prelude_picks_up_prelude_when_not_shadowed() {
        let mut reg = registry_from_prelude();
        let form = {
            let (forms, errs) = may_i_sexpr::parse(
                r#"(define-arg-style java (overrides gnu) (separators " " "=" ":"))"#,
            );
            assert!(errs.is_empty());
            forms.into_iter().next().unwrap()
        };
        reg.push(crate::style::parse_style_definition(&form).unwrap());
        let java = reg.resolve("java").unwrap();
        assert_eq!(java.long_prefix(), "--"); // from prelude gnu
        assert_eq!(java.separators(), &[" ", "=", ":"]);
    }
}

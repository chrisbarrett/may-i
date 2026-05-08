// Prelude `(define-arg-style …)` declarations, auto-loaded into every
// parsed config so user `:overrides gnu` resolves out of the box.
//
// User declarations come after prelude entries in `Config::style_specs`,
// so user `(define-arg-style gnu …)` shadows the prelude (last-wins
// per `StyleRegistry::get`).

use may_i_core::ast::StyleSpec;

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

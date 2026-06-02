// Prelude `(define-arg-style …)` and `(parser …)` declarations,
// auto-loaded into every parsed config so user `(overrides gnu)`
// resolves out of the box and common carrier tools (sudo, xargs, env,
// …) come pre-declared.
//
// User declarations come after prelude entries, so user
// `(define-arg-style gnu …)` or `(parser "sudo" …)` shadows the prelude
// (last-wins per the relevant registry).
//
// The prelude lives in `prelude.lisp` and is inlined at compile-time
// via `include_str!`. Edit the lisp file rather than this module when
// adding or tuning prelude declarations.

use may_i_core::ast::{Parser, Provenance, StyleSpec};
use may_i_sexpr::Sexpr;

const PRELUDE_SOURCE: &str = include_str!("prelude.lisp");

/// Parse the prelude and return its top-level forms. Panics on parse
/// errors — that's a build-time programming error, not user input.
fn prelude_forms() -> Vec<Sexpr> {
    let (forms, errs) = may_i_sexpr::parse(PRELUDE_SOURCE);
    assert!(errs.is_empty(), "prelude parse errors: {errs:?}");
    forms
}

/// Returns true if `form` is a `(TAG …)` list with the given head.
fn is_form(form: &Sexpr, tag: &str) -> bool {
    form.as_list()
        .and_then(|l| l.first())
        .and_then(|f| f.as_atom())
        == Some(tag)
}

/// Parse the prelude's `(define-arg-style …)` declarations.
pub fn prelude_style_specs() -> Vec<StyleSpec> {
    let mut specs = Vec::new();
    for form in prelude_forms()
        .iter()
        .filter(|f| is_form(f, "define-arg-style"))
    {
        let spec = crate::style::parse_style_definition(form)
            .expect("prelude define-arg-style failed to parse");
        specs.push(spec);
    }
    specs
}

/// Parse the prelude's `(parser …)` declarations. Each is tagged with
/// `Provenance::Prelude` so user `(parser …)` declarations that shadow
/// a prelude-shipped carrier do so silently.
pub fn prelude_parsers() -> Vec<Parser> {
    let mut parsers = Vec::new();
    for form in prelude_forms().iter().filter(|f| is_form(f, "parser")) {
        let mut parser = crate::parser_form::parse_parser_form(form)
            .expect("prelude parser declaration failed to parse");
        parser.provenance = Provenance::Prelude;
        parsers.push(parser);
    }
    parsers
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{FlagsMode, PunPolicy, StyleRegistry};

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

    #[test]
    fn parsers_include_sudo_with_posix_flags_mode() {
        let parsers = prelude_parsers();
        let sudo = parsers
            .iter()
            .find(|p| p.program == "sudo")
            .expect("sudo parser in prelude");
        assert_eq!(sudo.flags_mode, FlagsMode::Posix);
        assert_eq!(sudo.rest.as_ref().map(|b| b.as_str()), Some("cmd"));
        assert_eq!(sudo.style_name, "gnu");
        assert!(sudo.provenance.is_prelude());
    }

    #[test]
    fn third_party_carriers_excluded_from_prelude() {
        // Tools that don't ship with a regular Linux distribution
        // belong in user config unless their argv semantics are
        // silent-bypass footguns — mise / nix-shell / direnv / ssh
        // are exceptions because mis-parsing them leaks inner
        // commands past carrier rules. terragrunt is still
        // user-territory.
        let parsers = prelude_parsers();
        assert!(parsers.iter().all(|p| p.program != "terragrunt"));
    }

    #[test]
    fn parsers_include_nix_with_until_flags_mode() {
        let parsers = prelude_parsers();
        let nix = parsers
            .iter()
            .find(|p| p.program == "nix")
            .expect("nix parser in prelude");
        assert_eq!(
            nix.flags_mode,
            FlagsMode::Until(vec!["--command".to_string(), "-c".to_string()])
        );
        assert_eq!(nix.rest.as_ref().map(|b| b.as_str()), Some("cmd"));
        assert_eq!(nix.style_name, "gnu");
        assert!(nix.provenance.is_prelude());
    }

    #[test]
    fn user_parser_shadows_prelude_nix() {
        let cfg = crate::parse_config(
            r#"(parser "nix" (style gnu) (flags (until "--command")) (rest #cmd))"#,
        )
        .expect("config parses");
        let resolved = cfg.parser_for("nix");
        assert_eq!(
            resolved.flags_mode,
            FlagsMode::Until(vec!["--command".to_string()])
        );
    }

    #[test]
    fn prelude_nix_resolved_when_no_user_declaration() {
        let cfg = crate::parse_config("").expect("empty config parses");
        let resolved = cfg.parser_for("nix");
        assert_eq!(
            resolved.flags_mode,
            FlagsMode::Until(vec!["--command".to_string(), "-c".to_string()])
        );
    }

    #[test]
    fn parsers_include_timeout_with_duration_positional() {
        let parsers = prelude_parsers();
        let timeout = parsers
            .iter()
            .find(|p| p.program == "timeout")
            .expect("timeout parser in prelude");
        assert_eq!(timeout.flags_mode, FlagsMode::Posix);
        assert_eq!(timeout.positionals.len(), 1);
        assert_eq!(
            timeout.positionals[0].binding.as_ref().map(|b| b.as_str()),
            Some("duration")
        );
        assert_eq!(timeout.rest.as_ref().map(|b| b.as_str()), Some("cmd"));
    }

    #[test]
    fn parsers_include_ssh_with_host_positional() {
        let parsers = prelude_parsers();
        let ssh = parsers
            .iter()
            .find(|p| p.program == "ssh")
            .expect("ssh parser in prelude");
        assert_eq!(
            ssh.positionals[0].binding.as_ref().map(|b| b.as_str()),
            Some("host")
        );
    }

    #[test]
    fn parsers_include_bash_with_c_binding() {
        let parsers = prelude_parsers();
        let bash = parsers
            .iter()
            .find(|p| p.program == "bash")
            .expect("bash parser in prelude");
        assert_eq!(bash.flags_mode, FlagsMode::Permute);
        let c = bash
            .parameters
            .iter()
            .find(|p| p.names.iter().any(|n| n == "c"))
            .expect("c parameter");
        assert_eq!(c.binding.as_ref().map(|b| b.as_str()), Some("cmd"));
    }

    #[test]
    fn parsers_include_find_with_many_till_exec() {
        let parsers = prelude_parsers();
        let find = parsers
            .iter()
            .find(|p| p.program == "find")
            .expect("find parser in prelude");
        let exec = find
            .parameters
            .iter()
            .find(|p| p.names.iter().any(|n| n == "exec"))
            .expect("exec parameter on find");
        assert!(matches!(
            exec.capture,
            may_i_core::ast::Capture::ManyTill { .. }
        ));
    }
}

// v2 parser for the unified rule DSL.
// This parser implements the new syntax defined in the unified-rule-dsl design.

pub mod command;
pub mod config;
pub mod effect;
pub mod migrate;
pub mod pattern;
pub mod predicate;
pub mod resolve;
pub mod rule;

#[cfg(test)]
mod migration_tests;

pub use command::{parse_command_pattern, parse_command_pattern_from_atom};
pub use config::parse_config;
pub use effect::parse_effect;
pub use pattern::{parse_arg_pattern, parse_positional_arg};
pub use predicate::parse_predicate;
pub use rule::{parse_define, parse_rule, parse_shorthand_effect};

use may_i_core::v2::Spanned;
use may_i_sexpr::Sexpr;

/// Parse a spanned value from an s-expression.
pub fn spanned<T>(value: T, sexpr: &Sexpr) -> Spanned<T> {
    Spanned::new(value, sexpr.span())
}

/// Helper to check if an atom is a reserved keyword.
pub fn is_reserved_keyword(atom: &str) -> bool {
    matches!(
        atom,
        "rule"
            | "define"
            | "fact?"
            | "and"
            | "or"
            | "not"
            | "positional"
            | "exact"
            | "anywhere"
            | "forbidden"
            | "="
            | "effect"
            | "may-i"
            | "cond"
            | "when"
            | "unless"
            | "if"
            | "else"
            | "safe-env-vars"
            | "check"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_sexpr::Sexpr;

    #[test]
    fn spanned_creates_spanned_value() {
        let sexpr = Sexpr::Atom("test".to_string(), may_i_core::Span::new(5, 10));
        let spanned = spanned(42, &sexpr);
        assert_eq!(spanned.value, 42);
        assert_eq!(spanned.span.start, 5);
        assert_eq!(spanned.span.end, 10);
    }

    #[test]
    fn is_reserved_keyword_matches_rule() {
        assert!(is_reserved_keyword("rule"));
    }

    #[test]
    fn is_reserved_keyword_matches_define() {
        assert!(is_reserved_keyword("define"));
    }

    #[test]
    fn is_reserved_keyword_matches_fact() {
        assert!(is_reserved_keyword("fact?"));
    }

    #[test]
    fn is_reserved_keyword_matches_and() {
        assert!(is_reserved_keyword("and"));
    }

    #[test]
    fn is_reserved_keyword_matches_or() {
        assert!(is_reserved_keyword("or"));
    }

    #[test]
    fn is_reserved_keyword_matches_not() {
        assert!(is_reserved_keyword("not"));
    }

    #[test]
    fn is_reserved_keyword_matches_positional() {
        assert!(is_reserved_keyword("positional"));
    }

    #[test]
    fn is_reserved_keyword_matches_exact() {
        assert!(is_reserved_keyword("exact"));
    }

    #[test]
    fn is_reserved_keyword_matches_anywhere() {
        assert!(is_reserved_keyword("anywhere"));
    }

    #[test]
    fn is_reserved_keyword_matches_forbidden() {
        assert!(is_reserved_keyword("forbidden"));
    }

    #[test]
    fn is_reserved_keyword_matches_equals() {
        assert!(is_reserved_keyword("="));
    }

    #[test]
    fn is_reserved_keyword_matches_effect() {
        assert!(is_reserved_keyword("effect"));
    }

    #[test]
    fn is_reserved_keyword_matches_may_i() {
        assert!(is_reserved_keyword("may-i"));
    }

    #[test]
    fn is_reserved_keyword_matches_cond() {
        assert!(is_reserved_keyword("cond"));
    }

    #[test]
    fn is_reserved_keyword_matches_else() {
        assert!(is_reserved_keyword("else"));
    }

    #[test]
    fn is_reserved_keyword_matches_when() {
        assert!(is_reserved_keyword("when"));
    }

    #[test]
    fn is_reserved_keyword_matches_unless() {
        assert!(is_reserved_keyword("unless"));
    }

    #[test]
    fn is_reserved_keyword_matches_if() {
        assert!(is_reserved_keyword("if"));
    }

    #[test]
    fn is_reserved_keyword_matches_safe_env_vars() {
        assert!(is_reserved_keyword("safe-env-vars"));
    }

    #[test]
    fn is_reserved_keyword_matches_check() {
        assert!(is_reserved_keyword("check"));
    }

    #[test]
    fn is_reserved_keyword_does_not_match_custom() {
        assert!(!is_reserved_keyword("custom"));
        assert!(!is_reserved_keyword("git"));
        assert!(!is_reserved_keyword("push"));
    }
}

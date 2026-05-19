// Command pattern parser for the unified DSL.
// Task 2.1: Implement command pattern parser (literals, `or`, `regex`)

use may_i_core::pattern::CommandPattern;
use may_i_sexpr::{RawError, Sexpr};

/// Parse a command pattern from an atom string.
/// This is used when we already know the input is an atom.
pub(crate) fn parse_command_pattern_from_atom(atom: &str) -> Result<CommandPattern, RawError> {
    Ok(CommandPattern::Literal(atom.to_string()))
}

/// Parse a command pattern from an s-expression.
///
/// Syntax:
/// - `"git"` - literal match
/// - `(or "git" "gh")` - matches any of the listed commands
/// - `(regex "^git.*$")` - regex match
#[must_use = "parsed command pattern should be used"]
pub(crate) fn parse_command_pattern(sexpr: &Sexpr) -> Result<CommandPattern, RawError> {
    match sexpr {
        Sexpr::String(s, _) | Sexpr::Symbol(s, _) | Sexpr::Keyword(s, _) => {
            // Literal command name
            Ok(CommandPattern::Literal(s.clone()))
        }
        Sexpr::List(list, span) => {
            if list.is_empty() {
                return Err(RawError::new("empty command pattern", *span));
            }

            let tag = list[0].as_atom().ok_or_else(|| {
                RawError::new("command pattern tag must be an atom", list[0].span())
            })?;

            match tag {
                "or" => {
                    // Parse OR pattern: (or PATTERN ...)
                    if list.len() < 2 {
                        return Err(RawError::new("or must have at least one pattern", *span));
                    }

                    let patterns: Result<Vec<CommandPattern>, _> =
                        list[1..].iter().map(parse_command_pattern).collect();

                    Ok(CommandPattern::Or(patterns?))
                }
                "regex" => Err(
                    RawError::new("regex is not supported in command position", *span)
                        .with_help("use a literal command name or (or ...) instead"),
                ),
                other => Err(RawError::new(
                    format!("unknown command pattern form: {other}"),
                    list[0].span(),
                )
                .with_help("valid command patterns: literal string, (or ...), (regex ...)")),
            }
        }
        Sexpr::Vector(_, span) => Err(RawError::new(
            "command pattern does not support vector syntax",
            *span,
        )),
        Sexpr::Binding(_, span) => Err(RawError::new(
            "command position does not accept a binding reference",
            *span,
        )
        .with_help("use a literal command name, (or …), or (regex …)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::pattern::CommandPattern;
    use may_i_sexpr::RawError;

    fn parse(input: &str) -> Result<CommandPattern, RawError> {
        let (forms, errors) = may_i_sexpr::parse(input);
        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }
        if forms.len() != 1 {
            return Err(RawError::new(
                "expected exactly one form",
                may_i_core::Span::new(0, input.len()),
            ));
        }
        parse_command_pattern(&forms[0])
    }

    #[test]
    fn parse_literal_command() {
        let pattern = parse(r#""git""#).unwrap();
        match pattern {
            CommandPattern::Literal(s) => assert_eq!(s, "git"),
            _ => panic!("expected Literal"),
        }
    }

    #[test]
    fn parse_or_command() {
        let pattern = parse(r#"(or "git" "gh")"#).unwrap();
        match pattern {
            CommandPattern::Or(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(matches!(&patterns[0], CommandPattern::Literal(s) if s == "git"));
                assert!(matches!(&patterns[1], CommandPattern::Literal(s) if s == "gh"));
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn parse_regex_command_is_error() {
        let err = parse(r#"(regex "^git.*$")"#).expect_err("expected error");
        assert!(format!("{err}").contains("regex is not supported in command position"));
    }

    #[test]
    fn nested_or_patterns() {
        let pattern = parse(r#"(or "git" (or "gh" "hub"))"#).unwrap();
        match pattern {
            CommandPattern::Or(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(matches!(&patterns[0], CommandPattern::Literal(s) if s == "git"));
                // Second element is also an Or
                assert!(matches!(&patterns[1], CommandPattern::Or(_)));
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn parse_empty_command_pattern_error() {
        let err = parse(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty command pattern"));
    }

    #[test]
    fn parse_or_without_patterns_error() {
        let err = parse(r#"(or)"#).expect_err("expected error");
        assert!(format!("{err}").contains("or must have at least one pattern"));
    }

    #[test]
    fn parse_unknown_command_pattern_error() {
        let err = parse(r#"(unknown "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown command pattern form"));
    }

    #[test]
    fn parse_non_atom_tag_error() {
        let err = parse(r#"(("not an atom") "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("command pattern tag must be an atom"));
    }

    #[test]
    fn parse_vector_syntax_error() {
        let err = parse(r#"["test"]"#).expect_err("expected error");
        assert!(format!("{err}").contains("command pattern does not support vector syntax"));
    }

    #[test]
    fn rejects_non_selector_forms_in_command_position() {
        // positional, exact, anywhere, forbidden, etc. are not valid command selectors
        let err = parse(r#"(positional "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown command pattern form"));

        let err = parse(r#"(exact "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown command pattern form"));

        let err = parse(r#"(anywhere "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown command pattern form"));

        let err = parse(r#"(forbidden "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown command pattern form"));
    }
}

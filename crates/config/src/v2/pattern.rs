// Argument pattern parser for v2 DSL.
// Task 2.3: Implement argument pattern parsers (`positional`, `exact`, `anywhere`, `forbidden`)

use may_i_core::types::{Expr, Quantifier};
use may_i_core::v2::pattern::{ArgPattern, PositionalArg};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a simple expression pattern from an s-expression.
fn parse_expr(sexpr: &Sexpr) -> Result<Expr, RawError> {
    match sexpr {
        Sexpr::Atom(s, _) if s == "*" => Ok(Expr::Wildcard),
        Sexpr::Atom(s, _) => Ok(Expr::Literal(s.clone())),
        Sexpr::List(list, span) => {
            if list.is_empty() {
                return Err(RawError::new("empty expression form", *span));
            }
            let tag = list[0].as_atom().ok_or_else(|| {
                RawError::new("expression form tag must be an atom", list[0].span())
            })?;
            match tag {
                "regex" => {
                    if list.len() != 2 {
                        return Err(RawError::new("regex must have exactly one pattern", *span));
                    }
                    let pat = list[1].as_atom().ok_or_else(|| {
                        RawError::new("regex pattern must be a string", list[1].span())
                    })?;
                    let re = regex::Regex::new(pat).map_err(|e| {
                        RawError::new(format!("invalid regex '{pat}': {e}"), list[1].span())
                    })?;
                    Ok(Expr::Regex(re))
                }
                "or" => {
                    let exprs: Result<Vec<Expr>, _> = list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::Or(exprs?))
                }
                "and" => {
                    let exprs: Result<Vec<Expr>, _> = list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::And(exprs?))
                }
                "not" => {
                    if list.len() != 2 {
                        return Err(RawError::new("not must have exactly one expression", *span));
                    }
                    Ok(Expr::Not(Box::new(parse_expr(&list[1])?)))
                }
                other => Err(RawError::new(
                    format!("unknown expression form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised expression form")
                .with_help("valid expression forms: regex, or, and, not")),
            }
        }
        Sexpr::Vector(_, span) => Err(RawError::new(
            "expression forms do not support bracket syntax here",
            *span,
        )),
    }
}

/// Parse an argument pattern from an s-expression.
///
/// Syntax:
/// - `(positional PATTERN ... [. RECURSIVE])` - match positional args
/// - `(exact PATTERN ... [. RECURSIVE])` - match exact positional args
/// - `(anywhere PATTERN ...)` - token appears anywhere
/// - `(forbidden PATTERN ...)` - token must not appear
/// - `(= N PATTERN)` - match at specific position
pub fn parse_arg_pattern(sexpr: &Sexpr) -> Result<ArgPattern, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("argument pattern must be a list", sexpr.span()))?;

    if list.is_empty() {
        return Err(RawError::new("empty argument pattern", sexpr.span()));
    }

    let tag = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("argument pattern tag must be an atom", list[0].span()))?;

    match tag {
        "positional" => parse_positional_form(&list[1..], sexpr.span(), false),
        "exact" => parse_positional_form(&list[1..], sexpr.span(), true),
        "anywhere" => {
            let exprs: Result<Vec<Expr>, _> = list[1..].iter().map(parse_expr).collect();
            Ok(ArgPattern::Anywhere(exprs?))
        }
        "forbidden" => {
            let exprs: Result<Vec<Expr>, _> = list[1..].iter().map(parse_expr).collect();
            Ok(ArgPattern::Forbidden(exprs?))
        }
        "=" => {
            // Position-specific match: (= N PATTERN)
            if list.len() != 3 {
                return Err(RawError::new(
                    "= must have exactly a position number and a pattern",
                    sexpr.span(),
                ));
            }

            let pos_str = list[1]
                .as_atom()
                .ok_or_else(|| RawError::new("position must be a number", list[1].span()))?;

            let position: usize = pos_str.parse().map_err(|_| {
                RawError::new("position must be a positive integer", list[1].span())
            })?;

            if position == 0 {
                return Err(RawError::new(
                    "position must be 1 or greater (1-indexed)",
                    list[1].span(),
                ));
            }

            let pattern = parse_expr(&list[2])?;
            Ok(ArgPattern::At { position, pattern })
        }
        other => Err(
            RawError::new(format!("unknown argument pattern: {other}"), list[0].span())
                .with_help("valid argument patterns: positional, exact, anywhere, forbidden, ="),
        ),
    }
}

/// Parse positional/exact argument form, handling dot syntax for recursive evaluation.
fn parse_positional_form(
    args: &[Sexpr],
    _span: may_i_core::Span,
    exact: bool,
) -> Result<ArgPattern, RawError> {
    // Check for dot syntax indicating recursive evaluation target
    // Look for a `.` atom followed by the recursive pattern
    let mut pargs: Vec<PositionalArg> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        // Check for dot syntax: `.` followed by recursive pattern
        if let Some(atom) = args[i].as_atom()
            && atom == "."
            && i + 1 < args.len()
        {
            // Parse all items before the dot as positional args
            // The remaining item after dot should be a recursive pattern
            // For now, we just mark the last positional arg as recursive
            // or we could handle it differently based on design
            if !pargs.is_empty() {
                let last_idx = pargs.len() - 1;
                pargs[last_idx].recursive = true;
            }
            i += 2; // Skip dot and the recursive target
            continue;
        }

        pargs.push(parse_positional_arg(&args[i])?);
        i += 1;
    }

    if exact {
        Ok(ArgPattern::Exact(pargs))
    } else {
        Ok(ArgPattern::Positional(pargs))
    }
}

/// Parse a positional argument (with optional quantifier).
///
/// Syntax:
/// - `PATTERN` - single required argument
/// - `(? PATTERN)` - optional (0 or 1)
/// - `(+ PATTERN)` - one or more
/// - `(* PATTERN)` - zero or more
pub fn parse_positional_arg(sexpr: &Sexpr) -> Result<PositionalArg, RawError> {
    match sexpr {
        Sexpr::List(list, _) if !list.is_empty() => {
            let tag = list[0]
                .as_atom()
                .ok_or_else(|| RawError::new("quantifier tag must be an atom", list[0].span()))?;

            match tag {
                "?" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "? must have exactly one pattern",
                            sexpr.span(),
                        ));
                    }
                    let expr = parse_expr(&list[1])?;
                    Ok(PositionalArg::with_quantifier(expr, Quantifier::Optional))
                }
                "+" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "+ must have exactly one pattern",
                            sexpr.span(),
                        ));
                    }
                    let expr = parse_expr(&list[1])?;
                    Ok(PositionalArg::with_quantifier(expr, Quantifier::OneOrMore))
                }
                "*" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "* must have exactly one pattern",
                            sexpr.span(),
                        ));
                    }
                    let expr = parse_expr(&list[1])?;
                    Ok(PositionalArg::with_quantifier(expr, Quantifier::ZeroOrMore))
                }
                _ => {
                    // Not a quantifier form, treat as a list expression
                    let expr = parse_expr(sexpr)?;
                    Ok(PositionalArg::one(expr))
                }
            }
        }
        _ => {
            // Simple expression
            let expr = parse_expr(sexpr)?;
            Ok(PositionalArg::one(expr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_arg(input: &str) -> Result<ArgPattern, RawError> {
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
        parse_arg_pattern(&forms[0])
    }

    #[test]
    fn parse_positional_simple() {
        let pattern = parse_arg(r#"(positional "push")"#).unwrap();
        match pattern {
            ArgPattern::Positional(pargs) => {
                assert_eq!(pargs.len(), 1);
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_wildcard() {
        let pattern = parse_arg(r#"(positional "push" *)"#).unwrap();
        match pattern {
            ArgPattern::Positional(pargs) => {
                assert_eq!(pargs.len(), 2);
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_exact_pattern() {
        let pattern = parse_arg(r#"(exact "status")"#).unwrap();
        match pattern {
            ArgPattern::Exact(pargs) => {
                assert_eq!(pargs.len(), 1);
            }
            _ => panic!("expected Exact"),
        }
    }

    #[test]
    fn parse_anywhere_pattern() {
        let pattern = parse_arg(r#"(anywhere "--force")"#).unwrap();
        match pattern {
            ArgPattern::Anywhere(exprs) => {
                assert_eq!(exprs.len(), 1);
            }
            _ => panic!("expected Anywhere"),
        }
    }

    #[test]
    fn parse_forbidden_pattern() {
        let pattern = parse_arg(r#"(forbidden "--force")"#).unwrap();
        match pattern {
            ArgPattern::Forbidden(exprs) => {
                assert_eq!(exprs.len(), 1);
            }
            _ => panic!("expected Forbidden"),
        }
    }

    #[test]
    fn parse_at_position() {
        let pattern = parse_arg(r#"(= 1 "git")"#).unwrap();
        match pattern {
            ArgPattern::At { position, .. } => {
                assert_eq!(position, 1);
            }
            _ => panic!("expected At"),
        }
    }

    #[test]
    fn positional_with_quantifiers() {
        let pattern = parse_arg(r#"(positional "cmd" (? "arg") (+ "more"))"#).unwrap();
        match pattern {
            ArgPattern::Positional(pargs) => {
                assert_eq!(pargs.len(), 3);
                assert!(matches!(pargs[0].quantifier, Quantifier::One));
                assert!(matches!(pargs[1].quantifier, Quantifier::Optional));
                assert!(matches!(pargs[2].quantifier, Quantifier::OneOrMore));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn position_zero_is_error() {
        let err = parse_arg(r#"(= 0 "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("1 or greater"));
    }

    #[test]
    fn parse_empty_expr_form_error() {
        let err = parse_arg(r#"(positional (regex))"#).expect_err("expected error");
        assert!(format!("{err}").contains("regex must have exactly one pattern"));
    }

    #[test]
    fn parse_not_without_arg_error() {
        let err = parse_arg(r#"(positional (not))"#).expect_err("expected error");
        assert!(format!("{err}").contains("not must have exactly one expression"));
    }

    #[test]
    fn parse_unknown_expr_form_error() {
        let err = parse_arg(r#"(positional (unknown "test"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown expression form"));
    }

    #[test]
    fn parse_bracket_syntax_error() {
        let err = parse_arg(r#"(positional ["test"])"#).expect_err("expected error");
        assert!(format!("{err}").contains("bracket syntax"));
    }

    #[test]
    fn parse_empty_list_error() {
        let err = parse_arg(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty argument pattern"));
    }

    #[test]
    fn parse_invalid_position_type_error() {
        let err = parse_arg(r#"(= "one" "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("position must be a positive integer"));
    }

    #[test]
    fn parse_invalid_regex_error() {
        let err = parse_arg(r#"(positional (regex "[invalid"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("invalid regex"));
    }

    #[test]
    fn parse_non_atom_tag_error() {
        let err = parse_arg(r#"(("not an atom") "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("must be an atom"));
    }
}

// Argument pattern parser for v2 DSL.
// Task 2.3: Implement argument pattern parsers (`positional`, `exact`, `anywhere`, `forbidden`)

use may_i_core::Quantifier;
use may_i_core::types::Expr;
use may_i_core::v2::ast::Effect;
use may_i_core::v2::pattern::{ArgPattern, PositionalArg};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a simple expression pattern from an s-expression.
/// Uses V2Effect for cond branches.
fn parse_expr(sexpr: &Sexpr) -> Result<Expr<Effect>, RawError> {
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
                    let exprs: Result<Vec<Expr<Effect>>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::Or(exprs?))
                }
                "and" => {
                    let exprs: Result<Vec<Expr<Effect>>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::And(exprs?))
                }
                "not" => {
                    if list.len() != 2 {
                        return Err(RawError::new("not must have exactly one expression", *span));
                    }
                    Ok(Expr::Not(Box::new(parse_expr(&list[1])?)))
                }
                "cond" => {
                    // Parse cond branches: ((test effect) ... (else effect))
                    let mut branches = Vec::new();
                    for branch in &list[1..] {
                        let branch_list = branch.as_list().ok_or_else(|| {
                            RawError::new("cond branch must be a list", branch.span())
                        })?;
                        if branch_list.is_empty() {
                            return Err(RawError::new("empty cond branch", branch.span()));
                        }

                        let branch_tag = branch_list[0].as_atom();
                        if branch_tag == Some("else") {
                            // Else branch: (else effect)
                            if branch_list.len() != 2 {
                                return Err(RawError::new(
                                    "else branch must have exactly one effect",
                                    branch.span(),
                                ));
                            }
                            let effect = super::effect::parse_effect(&branch_list[1])?.value;
                            branches.push(may_i_core::types::ExprBranch {
                                test: Expr::Wildcard,
                                effect,
                            });
                        } else {
                            // Regular branch: (test effect)
                            if branch_list.len() != 2 {
                                return Err(RawError::new(
                                    "cond branch must have (test effect) form",
                                    branch.span(),
                                ));
                            }
                            let test = parse_expr(&branch_list[0])?;
                            let effect = super::effect::parse_effect(&branch_list[1])?.value;
                            branches.push(may_i_core::types::ExprBranch { test, effect });
                        }
                    }
                    Ok(Expr::Cond(branches))
                }
                "if" => {
                    // (if PRED THEN ELSE) -> Cond([(PRED, THEN), (Wildcard, ELSE)])
                    if list.len() != 4 {
                        return Err(RawError::new(
                            "if must have exactly 3 arguments: (if PRED THEN ELSE)",
                            *span,
                        ));
                    }
                    let pred = parse_expr(&list[1])?;
                    let then_eff = super::effect::parse_effect(&list[2])?.value;
                    let else_eff = super::effect::parse_effect(&list[3])?.value;
                    let branches = vec![
                        may_i_core::types::ExprBranch {
                            test: pred,
                            effect: then_eff,
                        },
                        may_i_core::types::ExprBranch {
                            test: Expr::Wildcard,
                            effect: else_eff,
                        },
                    ];
                    Ok(Expr::Cond(branches))
                }
                "when" => {
                    // (when PRED EFFECT) -> Cond([(PRED, EFFECT)])
                    if list.len() != 3 {
                        return Err(RawError::new(
                            "when must have exactly 2 arguments: (when PRED EFFECT)",
                            *span,
                        ));
                    }
                    let pred = parse_expr(&list[1])?;
                    let eff = super::effect::parse_effect(&list[2])?.value;
                    let branches = vec![may_i_core::types::ExprBranch {
                        test: pred,
                        effect: eff,
                    }];
                    Ok(Expr::Cond(branches))
                }
                "unless" => {
                    // (unless PRED EFFECT) -> Cond([(Not(PRED), EFFECT)])
                    if list.len() != 3 {
                        return Err(RawError::new(
                            "unless must have exactly 2 arguments: (unless PRED EFFECT)",
                            *span,
                        ));
                    }
                    let pred = parse_expr(&list[1])?;
                    let eff = super::effect::parse_effect(&list[2])?.value;
                    let branches = vec![may_i_core::types::ExprBranch {
                        test: Expr::Not(Box::new(pred)),
                        effect: eff,
                    }];
                    Ok(Expr::Cond(branches))
                }
                other => Err(RawError::new(
                    format!("unknown expression form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised expression form")
                .with_help("valid expression forms: regex, or, and, not, cond, if, when, unless")),
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
            let exprs: Result<Vec<Expr<Effect>>, _> = list[1..].iter().map(parse_expr).collect();
            Ok(ArgPattern::Anywhere(exprs?))
        }
        "forbidden" => {
            let exprs: Result<Vec<Expr<Effect>>, _> = list[1..].iter().map(parse_expr).collect();
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

/// Parse positional/exact argument form, handling dot syntax for continuation effects.
fn parse_positional_form(
    args: &[Sexpr],
    _span: may_i_core::Span,
    exact: bool,
) -> Result<ArgPattern, RawError> {
    // Check for dot syntax: patterns before dot, continuation effect after
    let mut patterns: Vec<PositionalArg> = Vec::new();
    let mut continuation: Option<may_i_core::v2::ast::Effect> = None;
    let mut i = 0;

    while i < args.len() {
        // Check for dot syntax: `.` followed by continuation effect
        if let Some(atom) = args[i].as_atom()
            && atom == "."
        {
            if i + 1 >= args.len() {
                return Err(RawError::new(
                    "dot notation requires an effect after the dot",
                    args[i].span(),
                ));
            }
            // Parse the continuation effect
            let spanned_effect = super::effect::parse_effect(&args[i + 1])?;
            continuation = Some(spanned_effect.value);
            i += 2;
            continue;
        }

        patterns.push(parse_positional_arg(&args[i])?);
        i += 1;
    }

    if exact {
        Ok(ArgPattern::Exact {
            patterns,
            continuation: continuation.map(Box::new),
        })
    } else {
        Ok(ArgPattern::Positional {
            patterns,
            continuation: continuation.map(Box::new),
        })
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
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_wildcard() {
        let pattern = parse_arg(r#"(positional "push" *)"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 2);
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_exact_pattern() {
        let pattern = parse_arg(r#"(exact "status")"#).unwrap();
        match pattern {
            ArgPattern::Exact {
                patterns: pargs, ..
            } => {
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
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
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

    #[test]
    fn parse_positional_with_or_expression() {
        let pattern = parse_arg(r#"(positional (or "a" "b"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Or(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_and_expression() {
        let pattern = parse_arg(r#"(positional (and "a" "b"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::And(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_not_expression() {
        let pattern = parse_arg(r#"(positional (not "a"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Not(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_optional_quantifier() {
        let pattern = parse_arg(r#"(positional (? "arg"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].quantifier, Quantifier::Optional));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_zero_or_more_quantifier() {
        let pattern = parse_arg(r#"(positional (* "arg"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].quantifier, Quantifier::ZeroOrMore));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_one_or_more_quantifier() {
        let pattern = parse_arg(r#"(positional (+ "arg"))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].quantifier, Quantifier::OneOrMore));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_unknown_arg_pattern_error() {
        let err = parse_arg(r#"(unknown "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown argument pattern"));
    }

    #[test]
    fn parse_with_too_many_args_error() {
        let err = parse_arg(r#"(= 1 "a" "b")"#).expect_err("expected error");
        assert!(format!("{err}").contains("= must have exactly"));
    }

    #[test]
    fn parse_empty_expression_form_error() {
        let err = parse_arg(r#"(positional ())"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty expression form"));
    }

    #[test]
    fn parse_non_atom_expr_tag_error() {
        let err = parse_arg(r#"(positional (("not an atom")))"#).expect_err("expected error");
        assert!(format!("{err}").contains("tag must be an atom"));
    }

    #[test]
    fn parse_positional_with_dot_notation() {
        // (positional "git" . (effect :allow))
        let pattern = parse_arg(r#"(positional "git" . (effect :allow))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns,
                continuation,
            } => {
                assert_eq!(patterns.len(), 1);
                assert!(continuation.is_some());
            }
            _ => panic!("expected Positional with continuation"),
        }
    }

    #[test]
    fn parse_positional_with_dot_notation_may_i() {
        // (positional * . (may-i (positional *)))
        let pattern = parse_arg(r#"(positional * . (may-i (positional *)))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns,
                continuation,
            } => {
                assert_eq!(patterns.len(), 1);
                assert!(continuation.is_some());
            }
            _ => panic!("expected Positional with may-i continuation"),
        }
    }

    #[test]
    fn parse_exact_with_dot_notation() {
        // (exact "git" "status" . (effect :allow))
        let pattern = parse_arg(r#"(exact "git" "status" . (effect :allow))"#).unwrap();
        match pattern {
            ArgPattern::Exact {
                patterns,
                continuation,
            } => {
                assert_eq!(patterns.len(), 2);
                assert!(continuation.is_some());
            }
            _ => panic!("expected Exact with continuation"),
        }
    }

    #[test]
    fn parse_positional_dot_without_effect_error() {
        // (positional "git" .)
        let err = parse_arg(r#"(positional "git" .)"#).expect_err("expected error");
        assert!(format!("{err}").contains("requires an effect after the dot"));
    }

    // --- Tests for fact binding (Expr::Bind) ---
    // Syntax: [:kw] or [:kw *] - both equivalent, brackets are visual distinction

    #[test]
    fn parse_positional_with_fact_binding_simple() {
        // (positional [:ssh/host] . (may-i *))
        // Bracket notation binds matched value to the keyword
        let pattern = parse_arg(r#"(positional [:ssh/host] . (may-i *))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                // The pattern should be a Bind expression with wildcard
                match &pargs[0].pattern {
                    Expr::Bind { key, expr } => {
                        assert_eq!(key, ":ssh/host");
                        assert!(matches!(expr.as_ref(), Expr::Wildcard));
                    }
                    other => panic!("expected Expr::Bind, got {:?}", other),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_fact_binding_explicit_wildcard() {
        // (positional [:ssh/host *] . (may-i *))
        // Explicit * is optional but allowed for clarity
        let pattern = parse_arg(r#"(positional [:ssh/host *] . (may-i *))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                match &pargs[0].pattern {
                    Expr::Bind { key, expr } => {
                        assert_eq!(key, ":ssh/host");
                        assert!(matches!(expr.as_ref(), Expr::Wildcard));
                    }
                    other => panic!("expected Expr::Bind, got {:?}", other),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_fact_binding_literal() {
        // (positional [:env "prod"])
        // Should bind the matched value to :env only if it equals "prod"
        let pattern = parse_arg(r#"(positional [:env "prod"])"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                match &pargs[0].pattern {
                    Expr::Bind { key, expr } => {
                        assert_eq!(key, ":env");
                        assert!(matches!(expr.as_ref(), Expr::Literal(s) if s == "prod"));
                    }
                    other => panic!("expected Expr::Bind, got {:?}", other),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_positional_with_fact_binding_regex() {
        // (positional [:ssh/host (regex "^prod-")])
        let pattern = parse_arg(r#"(positional [:ssh/host (regex "^prod-")])"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                match &pargs[0].pattern {
                    Expr::Bind { key, expr } => {
                        assert_eq!(key, ":ssh/host");
                        assert!(matches!(expr.as_ref(), Expr::Regex(_)));
                    }
                    other => panic!("expected Expr::Bind, got {:?}", other),
                }
            }
            _ => panic!("expected Positional"),
        }
    }
}

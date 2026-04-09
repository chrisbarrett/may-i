// Argument pattern parser for the unified DSL.
// Task 2.3: Implement argument pattern parsers (`positional`, `exact`, `anywhere`, `forbidden`)

use may_i_core::Quantifier;
use may_i_core::ast::Effect;
use may_i_core::pattern::{ArgPattern, PositionalArg};
use may_i_core::pattern::{Expr, ExprBranch};
use may_i_core::primitives::Keyword;
use may_i_sexpr::{RawError, Sexpr};

/// Check if an expression tree contains any Bind nodes.
fn contains_bind<E: std::fmt::Debug + may_i_core::ToDoc>(expr: &Expr<E>) -> bool {
    match expr {
        Expr::Bind { .. } => true,
        Expr::And(exprs) | Expr::Or(exprs) => exprs.iter().any(contains_bind),
        Expr::Not(inner) => contains_bind(inner),
        Expr::Cond(branches) => branches.iter().any(|b| contains_bind(&b.test)),
        Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => false,
        _ => false,
    }
}

/// Parse a simple expression pattern from an s-expression.
fn parse_expr(sexpr: &Sexpr) -> Result<Expr<Effect>, RawError> {
    match sexpr {
        Sexpr::Symbol(s, _) if s == "*" => Ok(Expr::Wildcard),
        Sexpr::String(s, _) | Sexpr::Symbol(s, _) | Sexpr::Keyword(s, _) => {
            Ok(Expr::Literal(s.clone()))
        }
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
                    let pat = list[1].as_atom_or_str().ok_or_else(|| {
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
                            let effect = crate::effect::parse_effect(&branch_list[1])?.value;
                            branches.push(ExprBranch {
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
                            let effect = crate::effect::parse_effect(&branch_list[1])?.value;
                            branches.push(ExprBranch { test, effect });
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
                    let then_eff = crate::effect::parse_effect(&list[2])?.value;
                    let else_eff = crate::effect::parse_effect(&list[3])?.value;
                    let branches = vec![
                        ExprBranch {
                            test: pred,
                            effect: then_eff,
                        },
                        ExprBranch {
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
                    let eff = crate::effect::parse_effect(&list[2])?.value;
                    let branches = vec![ExprBranch {
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
                    let eff = crate::effect::parse_effect(&list[2])?.value;
                    let branches = vec![ExprBranch {
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
        Sexpr::Vector(vector, _span) => {
            // Parse bracket notation as fact binding: [:keyword] or [:keyword EXPR]
            if vector.is_empty() {
                return Err(RawError::new("empty bracket vector is not valid", *_span));
            }

            // First element must be a keyword (starts with :)
            let key_str = vector[0].as_atom_or_str().ok_or_else(|| {
                RawError::new("fact binding key must be an atom", vector[0].span())
            })?;

            let keyword = Keyword::new(key_str).map_err(|e| {
                RawError::new(format!("invalid fact binding key: {e}"), vector[0].span())
            })?;

            // Parse the inner expression
            let inner_expr = if vector.len() == 1 {
                // [:keyword] alone means "bind anything" (wildcard)
                Expr::Wildcard
            } else if vector.len() == 2 {
                // [:keyword EXPR] - parse the expression
                parse_expr(&vector[1])?
            } else {
                return Err(RawError::new(
                    "fact binding must have form [:keyword] or [:keyword EXPR]",
                    Sexpr::Vector(vector.clone(), *_span).span(),
                ));
            };

            Ok(Expr::Bind {
                key: keyword,
                expr: Box::new(inner_expr),
            })
        }
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
            let exprs = exprs?;
            for (i, expr) in exprs.iter().enumerate() {
                if contains_bind(expr) {
                    let span = if i + 1 < list.len() {
                        list[i + 1].span()
                    } else {
                        sexpr.span()
                    };
                    return Err(RawError::new(
                        "fact binding is not valid in forbidden patterns",
                        span,
                    ));
                }
            }
            Ok(ArgPattern::Forbidden(exprs))
        }
        other => Err(
            RawError::new(format!("unknown argument pattern: {other}"), list[0].span())
                .with_help("valid argument patterns: positional, exact, anywhere, forbidden"),
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
    let mut continuation: Option<may_i_core::ast::Effect> = None;
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
            let spanned_effect = crate::effect::parse_effect(&args[i + 1])?;
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
    fn forbidden_rejects_bind() {
        let err = parse_arg(r#"(forbidden [:key *])"#).expect_err("expected error");
        assert!(format!("{err}").contains("not valid in forbidden"));
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
    fn parse_invalid_keyword_in_binding_error() {
        // Bracket syntax is now valid for fact binding, but non-keyword first elements should error
        let err = parse_arg(r#"(positional ["not-a-keyword"])"#).expect_err("expected error");
        assert!(format!("{err}").contains("invalid fact binding key"));
    }

    #[test]
    fn parse_empty_list_error() {
        let err = parse_arg(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty argument pattern"));
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
                        assert_eq!(key.as_str(), ":ssh/host");
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
                        assert_eq!(key.as_str(), ":ssh/host");
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
                        assert_eq!(key.as_str(), ":env");
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
                        assert_eq!(key.as_str(), ":ssh/host");
                        assert!(matches!(expr.as_ref(), Expr::Regex(_)));
                    }
                    other => panic!("expected Expr::Bind, got {:?}", other),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_empty_bracket_vector_error() {
        // Empty bracket vector should error
        let (sexprs, _) = may_i_sexpr::parse(r#"[]"#);
        let err = parse_expr(&sexprs[0]).expect_err("expected error");
        assert!(format!("{err}").contains("empty bracket vector"));
    }

    #[test]
    fn parse_bracket_with_non_keyword_error() {
        // Bracket with non-keyword first element should error
        let (sexprs, _) = may_i_sexpr::parse(r#"["not-a-keyword"]"#);
        let err = parse_expr(&sexprs[0]).expect_err("expected error");
        assert!(format!("{err}").contains("invalid fact binding key"));
    }

    #[test]
    fn parse_bracket_with_too_many_elements_error() {
        // Bracket with more than 2 elements should error
        let (sexprs, _) = may_i_sexpr::parse(r#"[:key a b]"#);
        let err = parse_expr(&sexprs[0]).expect_err("expected error");
        assert!(format!("{err}").contains("fact binding must have form"));
    }

    #[test]
    fn parse_fact_binding_nested_and() {
        // Test parsing [:key (and "a" "b")]
        let (sexprs, _) = may_i_sexpr::parse(r#"[:env (and "prod" "us")]"#);
        let expr = parse_expr(&sexprs[0]).unwrap();
        match expr {
            Expr::Bind { key, expr } => {
                assert_eq!(key.as_str(), ":env");
                match expr.as_ref() {
                    Expr::And(children) => {
                        assert_eq!(children.len(), 2);
                    }
                    _ => panic!("expected And"),
                }
            }
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn parse_fact_binding_nested_or() {
        // Test parsing [:key (or "a" "b")]
        let (sexprs, _) = may_i_sexpr::parse(r#"[:env (or "prod" "staging")]"#);
        let expr = parse_expr(&sexprs[0]).unwrap();
        match expr {
            Expr::Bind { key, expr } => {
                assert_eq!(key.as_str(), ":env");
                match expr.as_ref() {
                    Expr::Or(children) => {
                        assert_eq!(children.len(), 2);
                    }
                    _ => panic!("expected Or"),
                }
            }
            _ => panic!("expected Bind"),
        }
    }

    #[test]
    fn parse_fact_binding_nested_not() {
        // Test parsing [:key (not "exclude")]
        let (sexprs, _) = may_i_sexpr::parse(r#"[:env (not "exclude")]"#);
        let expr = parse_expr(&sexprs[0]).unwrap();
        match expr {
            Expr::Bind { key, expr } => {
                assert_eq!(key.as_str(), ":env");
                match expr.as_ref() {
                    Expr::Not(inner) => {
                        assert!(matches!(inner.as_ref(), Expr::Literal(_)));
                    }
                    _ => panic!("expected Not"),
                }
            }
            _ => panic!("expected Bind"),
        }
    }

    // --- Tests for cond/if/when/unless inside argument patterns ---

    #[test]
    fn parse_expr_cond_in_positional() {
        let pattern =
            parse_arg(r#"(positional (cond ("a" (effect :allow)) (else (effect :deny))))"#)
                .unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Cond(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_expr_if_in_positional() {
        let pattern = parse_arg(r#"(positional (if "a" (effect :allow) (effect :deny)))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Cond(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_expr_when_in_positional() {
        let pattern = parse_arg(r#"(positional (when "a" (effect :allow)))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Cond(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn parse_expr_unless_in_positional() {
        let pattern = parse_arg(r#"(positional (unless "a" (effect :deny)))"#).unwrap();
        match pattern {
            ArgPattern::Positional {
                patterns: pargs, ..
            } => {
                assert_eq!(pargs.len(), 1);
                assert!(matches!(pargs[0].pattern, Expr::Cond(_)));
            }
            _ => panic!("expected Positional"),
        }
    }

    // --- Error paths for cond/if/when/unless ---

    #[test]
    fn parse_cond_empty_branch_error() {
        let err = parse_arg(r#"(positional (cond ()))"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty cond branch"));
    }

    #[test]
    fn parse_cond_else_wrong_arity_error() {
        let err = parse_arg(r#"(positional (cond (else (effect :allow) (effect :deny))))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("else branch must have exactly one effect"));
    }

    #[test]
    fn parse_cond_branch_wrong_arity_error() {
        let err = parse_arg(r#"(positional (cond ("a" (effect :allow) "extra")))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("cond branch must have (test effect) form"));
    }

    #[test]
    fn parse_if_wrong_arity_error() {
        let err =
            parse_arg(r#"(positional (if "a" (effect :allow)))"#).expect_err("expected error");
        assert!(format!("{err}").contains("if must have exactly 3 arguments"));
    }

    #[test]
    fn parse_when_wrong_arity_error() {
        let err = parse_arg(r#"(positional (when "a"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("when must have exactly 2 arguments"));
    }

    #[test]
    fn parse_unless_wrong_arity_error() {
        let err = parse_arg(r#"(positional (unless "a"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("unless must have exactly 2 arguments"));
    }

    // --- Quantifier arity error paths ---

    #[test]
    fn parse_optional_quantifier_wrong_arity_error() {
        let err = parse_arg(r#"(positional (? "a" "b"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("? must have exactly one pattern"));
    }

    #[test]
    fn parse_one_or_more_quantifier_wrong_arity_error() {
        let err = parse_arg(r#"(positional (+ "a" "b"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("+ must have exactly one pattern"));
    }

    #[test]
    fn parse_zero_or_more_quantifier_wrong_arity_error() {
        let err = parse_arg(r#"(positional (* "a" "b"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("* must have exactly one pattern"));
    }

    // --- contains_bind coverage for Cond variant ---

    #[test]
    fn forbidden_rejects_bind_in_cond() {
        let err = parse_arg(r#"(forbidden (cond ([:key *] (effect :allow))))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("not valid in forbidden"));
    }

    // --- Property tests ---

    fn expr_eq(a: &Expr<may_i_core::Effect>, b: &Expr<may_i_core::Effect>) -> bool {
        match (a, b) {
            (Expr::Literal(a), Expr::Literal(b)) => a == b,
            (Expr::Wildcard, Expr::Wildcard) => true,
            (Expr::Regex(a), Expr::Regex(b)) => a.as_str() == b.as_str(),
            (Expr::And(a), Expr::And(b)) | (Expr::Or(a), Expr::Or(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| expr_eq(x, y))
            }
            (Expr::Not(a), Expr::Not(b)) => expr_eq(a, b),
            _ => false,
        }
    }

    fn is_simple_expr(expr: &Expr<may_i_core::Effect>) -> bool {
        match expr {
            Expr::Literal(_) | Expr::Wildcard | Expr::Regex(_) => true,
            Expr::And(es) | Expr::Or(es) => es.iter().all(is_simple_expr),
            Expr::Not(e) => is_simple_expr(e),
            Expr::Cond(_) | Expr::Bind { .. } => false,
            _ => false,
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 256, max_shrink_iters: 50, .. proptest::prelude::ProptestConfig::default() })]

        #[test]
        fn expr_display_parse_roundtrip(expr in may_i_core::test_generators::any_expr(3)) {
            proptest::prop_assume!(is_simple_expr(&expr));
            let text = format!("{}", expr);
            let (forms, errors) = may_i_sexpr::parse(&text);
            proptest::prop_assert!(errors.is_empty(), "sexpr parse failed: {:?}\ntext: {}", errors, text);
            proptest::prop_assert_eq!(forms.len(), 1, "expected 1 form, got {}\ntext: {}", forms.len(), text);

            let reparsed = parse_expr(&forms[0]);
            proptest::prop_assert!(reparsed.is_ok(), "parse_expr failed: {:?}\ntext: {}", reparsed.err(), text);
            let reparsed = reparsed.unwrap();
            proptest::prop_assert!(expr_eq(&expr, &reparsed),
                "roundtrip mismatch:\n  original: {:?}\n  text: {}\n  reparsed: {:?}",
                expr, text, reparsed);
        }
    }
}

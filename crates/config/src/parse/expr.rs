// Expression-level parsing: Expr, PosExpr, and their conditional sugar forms.

use may_i_sexpr::{RawError, Sexpr};
use may_i_core::Span;
use may_i_core::{Expr, ExprBranch, PosExpr, Quantifier};

pub(super) fn parse_pos_expr(sexpr: &Sexpr) -> Result<PosExpr, RawError> {
    if let Sexpr::List(list, _) = sexpr
        && list.len() == 2
        && let Some(tag) = list[0].as_atom()
    {
        let quantifier = match tag {
            "?" => Some(Quantifier::Optional),
            "+" => Some(Quantifier::OneOrMore),
            "*" => Some(Quantifier::ZeroOrMore),
            _ => None,
        };
        if let Some(q) = quantifier {
            return Ok(PosExpr { quantifier: q, expr: parse_expr(&list[1])? });
        }
    }
    Ok(PosExpr { quantifier: Quantifier::One, expr: parse_expr(sexpr)? })
}

pub(super) fn parse_expr(sexpr: &Sexpr) -> Result<Expr, RawError> {
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
                        return Err(RawError::new(
                            "regex must have exactly one pattern",
                            *span,
                        ));
                    }
                    let pat = list[1]
                        .as_atom()
                        .ok_or_else(|| {
                            RawError::new("regex pattern must be a string", list[1].span())
                        })?;
                    let re = regex::Regex::new(pat).map_err(|e| {
                        RawError::new(
                            format!("invalid regex '{pat}': {e}"),
                            list[1].span(),
                        )
                    })?;
                    Ok(Expr::Regex(re))
                }
                "or" => {
                    let exprs: Result<Vec<Expr>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::Or(exprs?))
                }
                "and" => {
                    let exprs: Result<Vec<Expr>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::And(exprs?))
                }
                "not" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "not must have exactly one expression",
                            *span,
                        ));
                    }
                    Ok(Expr::Not(Box::new(parse_expr(&list[1])?)))
                }
                "cond" => {
                    let branches = parse_expr_cond_branches(&list[1..])?;
                    Ok(Expr::Cond(branches))
                }
                "if" => parse_if_form(&list[1..], *span),
                "when" => parse_when_form(&list[1..], *span),
                "unless" => parse_unless_form(&list[1..], *span),
                other => Err(RawError::new(
                    format!("unknown expression form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised expression form")
                .with_help("valid expression forms: regex, or, and, not, cond, if, when, unless")),
            }
        }
    }
}

pub(super) fn parse_expr_cond_branches(branches: &[Sexpr]) -> Result<Vec<ExprBranch>, RawError> {
    let pairs = super::parse_cond_branches_generic(
        branches,
        Span::new(0, 0),
        parse_expr,
        || Expr::Wildcard,
    )?;
    Ok(pairs.into_iter().map(|(test, effect)| ExprBranch { test, effect }).collect())
}

fn parse_if_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    let (test, then_effect, else_effect) = super::parse_if_sugar(args, form_span, parse_expr)?;
    let mut branches = vec![ExprBranch { test, effect: then_effect }];
    if let Some(else_eff) = else_effect {
        branches.push(ExprBranch { test: Expr::Wildcard, effect: else_eff });
    }
    Ok(Expr::Cond(branches))
}

fn parse_when_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    let (test, effect) = super::parse_unary_sugar("when", args, form_span, parse_expr)?;
    Ok(Expr::Cond(vec![ExprBranch { test, effect }]))
}

fn parse_unless_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    let (test, effect) = super::parse_unary_sugar("unless", args, form_span, parse_expr)?;
    Ok(Expr::Cond(vec![ExprBranch { test: Expr::Not(Box::new(test)), effect }]))
}

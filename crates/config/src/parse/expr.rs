// Expression-level parsing: Expr, PosExpr, and their conditional sugar forms.

use may_i_sexpr::{RawError, Span, Sexpr};
use may_i_core::{Expr, ExprBranch, PosExpr};

pub(super) fn parse_pos_expr(sexpr: &Sexpr) -> Result<PosExpr, RawError> {
    if let Sexpr::List(list, _) = sexpr
        && list.len() == 2
        && let Some(tag) = list[0].as_atom()
    {
        match tag {
            "?" => return Ok(PosExpr::Optional(parse_expr(&list[1])?)),
            "+" => return Ok(PosExpr::OneOrMore(parse_expr(&list[1])?)),
            "*" => return Ok(PosExpr::ZeroOrMore(parse_expr(&list[1])?)),
            _ => {}
        }
    }
    Ok(PosExpr::One(parse_expr(sexpr)?))
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
    if branches.is_empty() {
        return Err(RawError::new(
            "cond must have at least one branch",
            Span::new(0, 0),
        ));
    }
    let mut result = Vec::new();
    for branch in branches {
        let items = branch.as_list().ok_or_else(|| {
            RawError::new("cond branch must be a list", branch.span())
        })?;
        if items.is_empty() {
            return Err(RawError::new("empty cond branch", branch.span()));
        }
        let test = match &items[0] {
            Sexpr::Atom(s, _) if s == "else" => Expr::Wildcard,
            other => parse_expr(other)?,
        };
        let mut effect = None;
        for item in &items[1..] {
            let il = item.as_list().ok_or_else(|| {
                RawError::new("cond branch element must be a list", item.span())
            })?;
            if il.is_empty() {
                return Err(RawError::new("empty cond branch element", item.span()));
            }
            let tag = il[0].as_atom().ok_or_else(|| {
                RawError::new("cond branch element tag must be an atom", il[0].span())
            })?;
            if tag == "effect" {
                effect = Some(super::parse_effect(il)?);
            } else {
                return Err(RawError::new(
                    format!("unknown cond branch element: {tag}"),
                    il[0].span(),
                ));
            }
        }
        result.push(ExprBranch {
            test,
            effect: effect.ok_or_else(|| {
                RawError::new("cond branch must have an effect", branch.span())
            })?,
        });
    }
    Ok(result)
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
    let (test, effect) = super::parse_when_sugar(args, form_span, parse_expr)?;
    Ok(Expr::Cond(vec![ExprBranch { test, effect }]))
}

fn parse_unless_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    let (test, effect) = super::parse_unless_sugar(args, form_span, parse_expr)?;
    Ok(Expr::Cond(vec![ExprBranch { test: Expr::Not(Box::new(test)), effect }]))
}

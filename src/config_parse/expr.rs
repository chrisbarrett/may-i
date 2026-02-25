// Expression-level parsing: Expr, PosExpr, and their conditional sugar forms.

use crate::errors::{RawError, Span};
use crate::sexpr::Sexpr;
use crate::types::{Expr, ExprBranch, PosExpr};

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
    if args.len() < 2 || args.len() > 3 {
        return Err(RawError::new(
            "if must have 2 or 3 arguments: (if EXPR EFFECT EFFECT?)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let then_list = args[1].as_list().ok_or_else(|| {
        RawError::new("if then-branch must be an effect list", args[1].span())
    })?;
    let then_effect = super::parse_effect(then_list)?;

    let mut branches = vec![ExprBranch { test, effect: then_effect }];

    if args.len() == 3 {
        let else_list = args[2].as_list().ok_or_else(|| {
            RawError::new("if else-branch must be an effect list", args[2].span())
        })?;
        let else_effect = super::parse_effect(else_list)?;
        branches.push(ExprBranch {
            test: Expr::Wildcard,
            effect: else_effect,
        });
    }

    Ok(Expr::Cond(branches))
}

fn parse_when_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "when must have exactly 2 arguments: (when EXPR EFFECT)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("when effect must be an effect list", args[1].span())
    })?;
    let effect = super::parse_effect(effect_list)?;
    Ok(Expr::Cond(vec![ExprBranch { test, effect }]))
}

fn parse_unless_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "unless must have exactly 2 arguments: (unless EXPR EFFECT)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("unless effect must be an effect list", args[1].span())
    })?;
    let effect = super::parse_effect(effect_list)?;
    Ok(Expr::Cond(vec![ExprBranch {
        test: Expr::Not(Box::new(test)),
        effect,
    }]))
}

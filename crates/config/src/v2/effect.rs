// Effect parser for v2 DSL.
// Task 2.6: Implement effect parser (`effect`, `may-i`, `case`, `when`, `unless`, `if`)

use may_i_core::v2::ast::{Effect, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse an effect from an s-expression list.
///
/// Syntax:
/// - `(effect :allow)` or `(effect :allow "reason")`
/// - `(effect :ask)` or `(effect :ask "reason")`
/// - `(effect :deny)` or `(effect :deny "reason")`
/// - `(may-i PATTERN)` - recursive evaluation
/// - `(case [(PREDICATE EFFECT) ...] [ELSE-EFFECT])`
/// - `(when PREDICATE EFFECT)`
/// - `(unless PREDICATE EFFECT)`
/// - `(if PREDICATE THEN-EFFECT [ELSE-EFFECT])`
pub fn parse_effect(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("effect must be a list", sexpr.span()))?;

    if list.is_empty() {
        return Err(RawError::new("empty effect", sexpr.span()));
    }

    let tag = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("effect tag must be an atom", list[0].span()))?;

    let effect = match tag {
        "effect" => parse_terminal_effect(&list[1..], sexpr.span())?,
        "may-i" => parse_may_i(&list[1..], sexpr.span())?,
        "case" => parse_case(&list[1..], sexpr.span())?,
        "when" => parse_when(&list[1..], sexpr.span())?,
        "unless" => parse_unless(&list[1..], sexpr.span())?,
        "if" => parse_if(&list[1..], sexpr.span())?,
        other => {
            return Err(
                RawError::new(format!("unknown effect form: {other}"), list[0].span())
                    .with_help("valid effects: effect, may-i, case, when, unless, if"),
            );
        }
    };

    Ok(Spanned::new(effect, sexpr.span()))
}

/// Parse a terminal effect (allow, ask, deny).
fn parse_terminal_effect(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new(
            "effect must have a keyword (:allow, :ask, or :deny)",
            span,
        ));
    }

    let kw = args[0]
        .as_atom()
        .ok_or_else(|| RawError::new("effect keyword must be an atom", args[0].span()))?;

    let reason = if args.len() > 1 {
        Some(
            args[1]
                .as_atom()
                .ok_or_else(|| RawError::new("effect reason must be a string", args[1].span()))?
                .to_string(),
        )
    } else {
        None
    };

    match kw {
        ":allow" => Ok(Effect::Allow(reason)),
        ":ask" => Ok(Effect::Ask(reason)),
        ":deny" => Ok(Effect::Deny(reason)),
        other => Err(
            RawError::new(format!("unknown effect keyword: {other}"), args[0].span())
                .with_help("valid effect keywords: :allow, :ask, :deny"),
        ),
    }
}

/// Parse a recursive evaluation effect.
fn parse_may_i(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 1 {
        return Err(RawError::new(
            "may-i must have exactly one argument pattern",
            span,
        ));
    }

    let pattern = super::pattern::parse_arg_pattern(&args[0])?;
    Ok(Effect::Evaluate(pattern))
}

/// Parse a case expression.
fn parse_case(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new("case must have at least one branch", span));
    }

    let mut branches = Vec::new();
    let mut fallback = None;

    for (i, arg) in args.iter().enumerate() {
        let branch_list = arg
            .as_list()
            .ok_or_else(|| RawError::new("case branch must be a list", arg.span()))?;

        if branch_list.is_empty() {
            return Err(RawError::new("empty case branch", arg.span()));
        }

        // Check for else branch
        if let Some(tag) = branch_list[0].as_atom()
            && tag == "else"
        {
            if i != args.len() - 1 {
                return Err(RawError::new(
                    "else branch must be the last branch",
                    arg.span(),
                ));
            }
            let else_effect = if branch_list.len() == 2 {
                parse_effect(&branch_list[1])?
            } else {
                return Err(RawError::new(
                    "else branch must have exactly one effect",
                    arg.span(),
                ));
            };
            fallback = Some(Box::new(else_effect));
            continue;
        }

        // Regular branch: (PREDICATE EFFECT)
        if branch_list.len() != 2 {
            return Err(RawError::new(
                "case branch must have exactly a predicate and an effect",
                arg.span(),
            ));
        }

        let predicate = super::predicate::parse_predicate(&branch_list[0])?;
        let effect = parse_effect(&branch_list[1])?;

        branches.push((Spanned::new(predicate, branch_list[0].span()), effect));
    }

    Ok(Effect::Case { branches, fallback })
}

/// Parse a when expression.
fn parse_when(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "when must have exactly a predicate and an effect: (when PREDICATE EFFECT)",
            span,
        ));
    }

    let predicate = super::predicate::parse_predicate(&args[0])?;
    let effect = parse_effect(&args[1])?;

    Ok(Effect::When {
        predicate: Spanned::new(predicate, args[0].span()),
        effect: Box::new(effect),
    })
}

/// Parse an unless expression.
fn parse_unless(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "unless must have exactly a predicate and an effect: (unless PREDICATE EFFECT)",
            span,
        ));
    }

    let predicate = super::predicate::parse_predicate(&args[0])?;
    let effect = parse_effect(&args[1])?;

    Ok(Effect::Unless {
        predicate: Spanned::new(predicate, args[0].span()),
        effect: Box::new(effect),
    })
}

/// Parse an if expression.
fn parse_if(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(RawError::new(
            "if must have 2 or 3 arguments: (if PREDICATE THEN-EFFECT [ELSE-EFFECT])",
            span,
        ));
    }

    let predicate = super::predicate::parse_predicate(&args[0])?;
    let then_effect = parse_effect(&args[1])?;
    let else_effect = if args.len() == 3 {
        Some(Box::new(parse_effect(&args[2])?))
    } else {
        None
    };

    Ok(Effect::If {
        predicate: Spanned::new(predicate, args[0].span()),
        then_effect: Box::new(then_effect),
        else_effect,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::v2::pattern::ArgPattern;

    fn parse_effect_str(input: &str) -> Result<Effect, RawError> {
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
        parse_effect(&forms[0]).map(|s| s.value)
    }

    #[test]
    fn parse_allow_effect() {
        let effect = parse_effect_str(r#"(effect :allow)"#).unwrap();
        match effect {
            Effect::Allow(reason) => assert!(reason.is_none()),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_allow_with_reason() {
        let effect = parse_effect_str(r#"(effect :allow "safe command")"#).unwrap();
        match effect {
            Effect::Allow(reason) => assert_eq!(reason.as_deref(), Some("safe command")),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_ask_effect() {
        let effect = parse_effect_str(r#"(effect :ask "confirm")"#).unwrap();
        match effect {
            Effect::Ask(reason) => assert_eq!(reason.as_deref(), Some("confirm")),
            _ => panic!("expected Ask"),
        }
    }

    #[test]
    fn parse_deny_effect() {
        let effect = parse_effect_str(r#"(effect :deny "dangerous")"#).unwrap();
        match effect {
            Effect::Deny(reason) => assert_eq!(reason.as_deref(), Some("dangerous")),
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn parse_may_i_effect() {
        let effect = parse_effect_str(r#"(may-i (positional *))"#).unwrap();
        match effect {
            Effect::Evaluate(_) => {}
            _ => panic!("expected Evaluate"),
        }
    }

    #[test]
    fn parse_when_effect() {
        let effect = parse_effect_str(r#"(when (has :via/ssh) (effect :allow))"#).unwrap();
        match effect {
            Effect::When { .. } => {}
            _ => panic!("expected When"),
        }
    }

    #[test]
    fn parse_unless_effect() {
        let effect = parse_effect_str(r#"(unless (has :dangerous) (effect :allow))"#).unwrap();
        match effect {
            Effect::Unless { .. } => {}
            _ => panic!("expected Unless"),
        }
    }

    #[test]
    fn parse_if_effect() {
        let effect =
            parse_effect_str(r#"(if (has :via/ssh) (effect :allow) (effect :ask))"#).unwrap();
        match effect {
            Effect::If { else_effect, .. } => {
                assert!(else_effect.is_some());
            }
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn parse_case_effect() {
        let effect = parse_effect_str(
            r#"
            (case
                [(has :via/ssh) (effect :allow)]
                [(positional "push") (effect :ask)]
                [else (effect :deny)])
        "#,
        )
        .unwrap();

        match effect {
            Effect::Case { branches, fallback } => {
                assert_eq!(branches.len(), 2);
                assert!(fallback.is_some());
            }
            _ => panic!("expected Case"),
        }
    }

    #[test]
    fn case_else_not_last_is_error() {
        let err = parse_effect_str(
            r#"
            (case
                [else (effect :deny)]
                [(has :via/ssh) (effect :allow)])
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("last branch"));
    }

    #[test]
    fn parse_may_i_with_exact_pattern() {
        let effect = parse_effect_str(r#"(may-i (exact "git" "push"))"#).unwrap();
        match effect {
            Effect::Evaluate(ArgPattern::Exact(_)) => {}
            _ => panic!("expected Evaluate with Exact pattern"),
        }
    }

    #[test]
    fn parse_case_without_else() {
        let effect = parse_effect_str(
            r#"
            (case
                [(has :via/ssh) (effect :allow)]
                [(positional "push") (effect :ask)])
        "#,
        )
        .unwrap();

        match effect {
            Effect::Case { branches, fallback } => {
                assert_eq!(branches.len(), 2);
                assert!(fallback.is_none());
            }
            _ => panic!("expected Case without fallback"),
        }
    }

    #[test]
    fn parse_if_without_else() {
        let effect = parse_effect_str(r#"(if (has :via/ssh) (effect :allow))"#).unwrap();
        match effect {
            Effect::If { else_effect, .. } => {
                assert!(else_effect.is_none());
            }
            _ => panic!("expected If without else"),
        }
    }

    #[test]
    fn parse_nested_effects() {
        let effect = parse_effect_str(
            r#"
            (when (has :via/ssh)
                (case
                    [(positional "push") (effect :ask)]
                    [else (effect :allow)]))
        "#,
        )
        .unwrap();

        match effect {
            Effect::When { effect: inner, .. } => {
                assert!(matches!(inner.value, Effect::Case { .. }));
            }
            _ => panic!("expected When with nested Case"),
        }
    }

    #[test]
    fn invalid_effect_keyword_is_error() {
        let err = parse_effect_str(r#"(effect :invalid)"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown effect keyword"));
    }

    #[test]
    fn may_i_without_pattern_is_error() {
        let err = parse_effect_str(r#"(may-i)"#).expect_err("expected error");
        assert!(format!("{err}").contains("pattern"));
    }
}

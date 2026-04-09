// Effect parser for the unified DSL.
// All effect forms evaluate to Decision | Nil.

use crate::is_reserved_keyword;
use may_i_core::ast::{Effect, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse an effect from an s-expression list.
///
/// Syntax:
/// - Terminal effects: `(effect :allow)`, `(effect :ask)`, `(effect :deny)` with optional reason
/// - Pattern effects: command strings, `(positional ...)`, `(exact ...)`, `(anywhere ...)`, `(forbidden ...)`
/// - Combinators: `(and EFFECT ...)`, `(or EFFECT ...)`, `(not EFFECT)`
/// - Conditionals: `(when PREDICATE EFFECT)`, `(unless PREDICATE EFFECT)`, `(if PREDICATE THEN ELSE)`, `(cond ...)`
/// - Recursion: `(may-i PATTERN)`
pub fn parse_effect(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError> {
    // Handle bare atoms and string literals: command literals
    if let Some(atom) = sexpr.as_atom_or_str()
        && !is_reserved_keyword(atom)
    {
        // This is a command literal - treat as CommandPattern effect
        let pattern = crate::command::parse_command_pattern_from_atom(atom)?;
        return Ok(Spanned::new(Effect::CommandPattern(pattern), sexpr.span()));
    }

    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("effect must be a list or command literal", sexpr.span()))?;

    if list.is_empty() {
        return Err(RawError::new("empty effect", sexpr.span()));
    }

    let tag = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("effect tag must be an atom", list[0].span()))?;

    let effect = match tag {
        "effect" => parse_terminal_effect(&list[1..], sexpr.span())?,
        "may-i" => parse_may_i(&list[1..], sexpr.span())?,
        "cond" => parse_cond(&list[1..], sexpr.span())?,
        "when" => parse_when(&list[1..], sexpr.span())?,
        "unless" => parse_unless(&list[1..], sexpr.span())?,
        "if" => parse_if(&list[1..], sexpr.span())?,
        "and" => parse_and(&list[1..], sexpr.span())?,
        "not" => parse_not(&list[1..], sexpr.span())?,
        // Pattern effects
        "positional" | "exact" | "anywhere" | "forbidden" | "=" => {
            let pattern = crate::pattern::parse_arg_pattern(sexpr)?;
            Effect::ArgPattern(pattern)
        }
        // "or" can be either a command pattern or an effect combinator
        "or" => {
            // Check if this is a command pattern (or "git" "gh") - all args are simple atoms
            if list.len() > 1 && is_command_or_pattern(&list[1..]) {
                let patterns: Result<Vec<_>, _> = list[1..]
                    .iter()
                    .map(|s| {
                        s.as_atom_or_str()
                            .ok_or_else(|| {
                                RawError::new(
                                    "command or pattern requires atom arguments",
                                    s.span(),
                                )
                            })
                            .and_then(crate::command::parse_command_pattern_from_atom)
                    })
                    .collect();
                Effect::CommandPattern(may_i_core::pattern::CommandPattern::Or(patterns?))
            } else {
                // It's an effect combinator
                parse_or(&list[1..], sexpr.span())?
            }
        }
        other => {
            // Try to parse as a command pattern (for complex command patterns)
            if let Ok(pattern) = crate::command::parse_command_pattern(sexpr) {
                Effect::CommandPattern(pattern)
            } else {
                return Err(
                    RawError::new(format!("unknown effect form: {other}"), list[0].span())
                        .with_help("valid effects: effect, may-i, cond, when, unless, if, and, or, not, positional, exact, anywhere, forbidden"),
                );
            }
        }
    };

    Ok(Spanned::new(effect, sexpr.span()))
}

/// Check if all sexprs are simple atoms (for command or pattern detection).
fn is_command_or_pattern(exprs: &[Sexpr]) -> bool {
    exprs.iter().all(|e| e.as_atom_or_str().is_some())
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
                .as_atom_or_str()
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

    // Allow bare `*` as shorthand for `(positional *)` - pass everything unconsumed down
    let pattern = if let Some("*") = args[0].as_atom() {
        use may_i_core::pattern::Expr;
        use may_i_core::pattern::{ArgPattern, PositionalArg};
        ArgPattern::Positional {
            patterns: vec![PositionalArg::one(Expr::Wildcard)],
            continuation: None,
        }
    } else {
        crate::pattern::parse_arg_pattern(&args[0])?
    };
    Ok(Effect::MayI { pattern })
}

/// Parse a cond expression (renamed from case).
fn parse_cond(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new("cond must have at least one branch", span));
    }

    let mut branches = Vec::new();
    let mut fallback = None;

    for (i, arg) in args.iter().enumerate() {
        let branch_list = arg
            .as_list()
            .ok_or_else(|| RawError::new("cond branch must be a list", arg.span()))?;

        if branch_list.is_empty() {
            return Err(RawError::new("empty cond branch", arg.span()));
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
                "cond branch must have exactly a predicate and an effect",
                arg.span(),
            ));
        }

        let predicate = crate::predicate::parse_predicate(&branch_list[0])?;
        let effect = parse_effect(&branch_list[1])?;

        branches.push((Spanned::new(predicate, branch_list[0].span()), effect));
    }

    Ok(Effect::Cond { branches, fallback })
}

/// Parse a when expression.
fn parse_when(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "when must have exactly a predicate and an effect: (when PREDICATE EFFECT)",
            span,
        ));
    }

    let predicate = crate::predicate::parse_predicate(&args[0])?;
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

    let predicate = crate::predicate::parse_predicate(&args[0])?;
    let effect = parse_effect(&args[1])?;

    Ok(Effect::Unless {
        predicate: Spanned::new(predicate, args[0].span()),
        effect: Box::new(effect),
    })
}

/// Parse an if expression.
fn parse_if(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 3 {
        return Err(RawError::new(
            "if must have exactly 3 arguments: (if PREDICATE THEN-EFFECT ELSE-EFFECT)",
            span,
        ));
    }

    let predicate = crate::predicate::parse_predicate(&args[0])?;
    let then_effect = parse_effect(&args[1])?;
    let else_effect = parse_effect(&args[2])?;

    Ok(Effect::If {
        predicate: Spanned::new(predicate, args[0].span()),
        then_effect: Box::new(then_effect),
        else_effect: Box::new(else_effect),
    })
}

/// Parse an and expression.
/// Syntax: `(and EFFECT ...)` - all effects must return non-Nil
fn parse_and(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new(
            "and must have at least one effect: (and EFFECT+)",
            span,
        ));
    }

    let effects = args
        .iter()
        .map(parse_effect)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Effect::And { effects })
}

/// Parse an or expression.
/// Syntax: `(or EFFECT ...)` - returns first non-Nil effect
fn parse_or(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new(
            "or must have at least one effect: (or EFFECT+)",
            span,
        ));
    }

    let effects = args
        .iter()
        .map(parse_effect)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Effect::Or { effects })
}

/// Parse a not expression.
/// Syntax: `(not EFFECT)` - inverts Allow/Nil, passes through Ask/Deny
fn parse_not(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 1 {
        return Err(RawError::new(
            "not must have exactly one effect: (not EFFECT)",
            span,
        ));
    }

    let effect = parse_effect(&args[0])?;

    Ok(Effect::Not {
        effect: Box::new(effect),
    })
}

#[cfg(test)]
mod tests {
    use crate::*;
    use may_i_core::ast::Effect;
    use may_i_core::pattern::ArgPattern;
    use may_i_sexpr::RawError;

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
            Effect::MayI { .. } => {}
            _ => panic!("expected MayI"),
        }
    }

    #[test]
    fn parse_may_i_with_bare_star_shorthand() {
        // Bare `*` is shorthand for `(positional *)` - pass everything unconsumed down
        let effect = parse_effect_str(r#"(may-i *)"#).unwrap();
        match effect {
            Effect::MayI { pattern } => {
                // Verify it produces the same pattern as (may-i (positional *))
                match pattern {
                    ArgPattern::Positional {
                        patterns,
                        continuation,
                    } => {
                        assert_eq!(patterns.len(), 1);
                        assert!(continuation.is_none());
                    }
                    _ => panic!("expected Positional pattern, got {:?}", pattern),
                }
            }
            _ => panic!("expected MayI effect, got {:?}", effect),
        }
    }

    #[test]
    fn parse_when_effect() {
        let effect = parse_effect_str(r#"(when (fact? :via/ssh) (effect :allow))"#).unwrap();
        match effect {
            Effect::When { .. } => {}
            _ => panic!("expected When"),
        }
    }

    #[test]
    fn parse_unless_effect() {
        let effect = parse_effect_str(r#"(unless (fact? :dangerous) (effect :allow))"#).unwrap();
        match effect {
            Effect::Unless { .. } => {}
            _ => panic!("expected Unless"),
        }
    }

    #[test]
    fn parse_if_effect() {
        let effect =
            parse_effect_str(r#"(if (fact? :via/ssh) (effect :allow) (effect :ask))"#).unwrap();
        match effect {
            Effect::If { .. } => {}
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn parse_cond_effect() {
        let effect = parse_effect_str(
            r#"
            (cond
                ((fact? :via/ssh) (effect :allow))
                ((positional "push") (effect :ask))
                (else (effect :deny)))
        "#,
        )
        .unwrap();

        match effect {
            Effect::Cond { branches, fallback } => {
                assert_eq!(branches.len(), 2);
                assert!(fallback.is_some());
            }
            _ => panic!("expected Cond"),
        }
    }

    #[test]
    fn parse_positional_as_effect() {
        // Positional patterns are now effects too
        let effect = parse_effect_str(r#"(positional "push")"#).unwrap();
        match effect {
            Effect::ArgPattern(ArgPattern::Positional { .. }) => {}
            _ => panic!("expected ArgPattern::Positional"),
        }
    }

    #[test]
    fn parse_and_effect() {
        let effect = parse_effect_str(r#"(and (positional "push") (effect :allow))"#).unwrap();
        match effect {
            Effect::And { effects } => {
                assert_eq!(effects.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn parse_or_effect() {
        let effect = parse_effect_str(r#"(or (positional "push") (effect :allow))"#).unwrap();
        match effect {
            Effect::Or { effects } => {
                assert_eq!(effects.len(), 2);
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn parse_not_effect() {
        let effect = parse_effect_str(r#"(not (positional "push"))"#).unwrap();
        match effect {
            Effect::Not { .. } => {}
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn cond_else_not_last_is_error() {
        let err = parse_effect_str(
            r#"
            (cond
                (else (effect :deny))
                ((fact? :via/ssh) (effect :allow)))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("last branch"));
    }

    #[test]
    fn parse_may_i_with_exact_pattern() {
        let effect = parse_effect_str(r#"(may-i (exact "git" "push"))"#).unwrap();
        match effect {
            Effect::MayI { .. } => {}
            _ => panic!("expected MayI with Exact pattern"),
        }
    }

    #[test]
    fn parse_cond_without_else() {
        let effect = parse_effect_str(
            r#"
            (cond
                ((fact? :via/ssh) (effect :allow))
                ((positional "push") (effect :ask)))
        "#,
        )
        .unwrap();

        match effect {
            Effect::Cond { branches, fallback } => {
                assert_eq!(branches.len(), 2);
                assert!(fallback.is_none());
            }
            _ => panic!("expected Cond without fallback"),
        }
    }

    #[test]
    fn parse_nested_effects() {
        let effect = parse_effect_str(
            r#"
            (when (fact? :via/ssh)
                (cond
                    ((positional "push") (effect :ask))
                    (else (effect :allow))))
        "#,
        )
        .unwrap();

        match effect {
            Effect::When { effect: inner, .. } => {
                assert!(matches!(inner.value, Effect::Cond { .. }));
            }
            _ => panic!("expected When with nested Cond"),
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

    #[test]
    fn empty_effect_error() {
        let err = parse_effect_str(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty effect"));
    }

    #[test]
    fn non_keyword_atom_as_command() {
        // Non-reserved atoms should be treated as command patterns
        let effect = parse_effect_str(r#"git"#).unwrap();
        assert!(matches!(effect, Effect::CommandPattern(_)));
    }

    #[test]
    fn reserved_keyword_atom_is_not_command() {
        // Reserved keywords as bare atoms should not be treated as commands
        let err = parse_effect_str(r#"rule"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect must be a list or command literal"));
    }

    #[test]
    fn unknown_effect_form_error() {
        let err = parse_effect_str(r#"(unknown)"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown effect form"));
    }

    #[test]
    fn effect_without_keyword_error() {
        let err = parse_effect_str(r#"(effect)"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect must have a keyword"));
    }

    #[test]
    fn effect_non_atom_keyword_error() {
        let err = parse_effect_str(r#"(effect ("not an atom"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect keyword must be an atom"));
    }

    #[test]
    fn effect_with_non_atom_reason_error() {
        let err =
            parse_effect_str(r#"(effect :allow ("not an atom"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect reason must be a string"));
    }

    #[test]
    fn may_i_with_too_many_args_error() {
        let err = parse_effect_str(r#"(may-i (positional *) (positional *))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("may-i must have exactly one"));
    }

    #[test]
    fn cond_empty_error() {
        let err = parse_effect_str(r#"(cond)"#).expect_err("expected error");
        assert!(format!("{err}").contains("cond must have at least one branch"));
    }

    #[test]
    fn cond_non_list_branch_error() {
        let err = parse_effect_str(r#"(cond :not-a-list)"#).expect_err("expected error");
        assert!(format!("{err}").contains("cond branch must be a list"));
    }

    #[test]
    fn cond_empty_branch_error() {
        let err = parse_effect_str(r#"(cond ())"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty cond branch"));
    }

    #[test]
    fn cond_else_with_too_many_effects_error() {
        let err = parse_effect_str(r#"(cond (else (effect :allow) (effect :deny)))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("else branch must have exactly one effect"));
    }

    #[test]
    fn cond_branch_with_wrong_arg_count_error() {
        let err = parse_effect_str(r#"(cond ((fact? :via/ssh)))"#).expect_err("expected error");
        assert!(
            format!("{err}").contains("cond branch must have exactly a predicate and an effect")
        );
    }

    #[test]
    fn when_with_wrong_arg_count_error() {
        let err = parse_effect_str(r#"(when (fact? :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("when must have exactly"));
    }

    #[test]
    fn when_with_too_many_args_error() {
        let err = parse_effect_str(r#"(when (fact? :via/ssh) (effect :allow) (effect :deny))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("when must have exactly"));
    }

    #[test]
    fn unless_with_wrong_arg_count_error() {
        let err = parse_effect_str(r#"(unless (fact? :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("unless must have exactly"));
    }

    #[test]
    fn if_with_too_few_args_error() {
        let err = parse_effect_str(r#"(if (fact? :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("if must have exactly 3 arguments"));
    }

    #[test]
    fn if_with_too_many_args_error() {
        let err = parse_effect_str(
            r#"(if (fact? :via/ssh) (effect :allow) (effect :deny) (effect :ask))"#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("if must have exactly 3 arguments"));
    }
}

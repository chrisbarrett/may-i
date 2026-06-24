// Effect parser for the unified DSL.
// All effect forms evaluate to Decision | Nil.

use crate::is_reserved_keyword;
use may_i_core::Decision;
use may_i_core::ast::{BindingName, Effect, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse an effect from an s-expression list.
///
/// Syntax:
/// - Terminal effects: `(allow)`, `(ask)`, `(deny)` with optional reason
/// - Pattern effects: command strings, `(positional ...)`, `(exact ...)`, `(anywhere ...)`, `(forbidden ...)`
/// - Combinators: `(and BODY ...)`, `(or BODY ...)`, `(not BODY)`
/// - Conditionals: `(when PREDICATE BODY)`, `(unless PREDICATE BODY)`, `(if PREDICATE THEN ELSE)`, `(cond ...)`
/// - Recursion: `(authorise)` (inside a host context)
#[must_use = "parsed effect should be used"]
pub(crate) fn parse_effect(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError> {
    // Handle string literals: always command literals (even if they match a reserved word).
    if let Some(s) = sexpr.as_str() {
        let pattern = crate::command::parse_command_pattern_from_atom(s)?;
        return Ok(Spanned::new(Effect::CommandPattern(pattern), sexpr.span()));
    }

    // Handle bare atoms: command literals unless they're reserved keywords.
    if let Some(atom) = sexpr.as_atom()
        && !is_reserved_keyword(atom)
    {
        let pattern = crate::command::parse_command_pattern_from_atom(atom)?;
        return Ok(Spanned::new(Effect::CommandPattern(pattern), sexpr.span()));
    }

    let list = sexpr.as_list().ok_or_else(|| {
        RawError::new(
            "a rule body must be a list or command literal",
            sexpr.span(),
        )
    })?;

    if list.is_empty() {
        return Err(RawError::new("empty rule body", sexpr.span()));
    }

    let tag = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("rule-body form tag must be an atom", list[0].span()))?;

    let effect = match tag {
        "effect" => {
            return Err(RawError::new(
                "(effect :decision …) is retired; use (allow|ask|deny REASON?)",
                list[0].span(),
            )
            .with_help("run `may-i migrate` to convert legacy syntax"));
        }
        "allow" => parse_decision_verb(Decision::Allow, &list[1..], sexpr.span())?,
        "ask" => parse_decision_verb(Decision::Ask, &list[1..], sexpr.span())?,
        "deny" => parse_decision_verb(Decision::Deny, &list[1..], sexpr.span())?,
        "may-i" => {
            return Err(RawError::new(
                "(may-i …) is retired; use (authorise) inside a host context",
                list[0].span(),
            )
            .with_help("run `may-i migrate` to convert legacy syntax"));
        }
        "authorise" => {
            // `(authorise #var)` — the parser-named-bindings rule-body
            // form. Exactly one argument, which must be a binding atom
            // referring to a parser-declared name.
            if list.len() != 2 {
                return Err(RawError::new(
                    "(authorise) requires exactly one binding reference",
                    list[0].span(),
                )
                .with_help(
                    "(authorise #cmd) — `#cmd` must be declared by the parser via (rest …), \
                     (parameter NAME #cmd), or (positional #cmd …)",
                ));
            }
            let raw = list[1].as_binding().ok_or_else(|| {
                RawError::new(
                    "(authorise …) takes a binding reference (e.g. #cmd)",
                    list[1].span(),
                )
            })?;
            let binding = BindingName::parse(raw).map_err(|e| {
                RawError::new(format!("invalid binding reference: {e}"), list[1].span())
            })?;
            Effect::Authorise {
                binding,
                binding_span: list[1].span(),
            }
        }
        "cond" => parse_cond(&list[1..], sexpr.span())?,
        "when" => parse_when(&list[1..], sexpr.span())?,
        "unless" => parse_unless(&list[1..], sexpr.span())?,
        "if" => parse_if(&list[1..], sexpr.span())?,
        "and" => parse_and(&list[1..], sexpr.span())?,
        "not" => parse_not(&list[1..], sexpr.span())?,
        // Pattern effects
        "positional" | "exact" | "anywhere" | "forbidden" | "flag" | "parameter" | "tail" | "=" => {
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
                    RawError::new(format!("unknown rule-body form: {other}"), list[0].span())
                        .with_help("valid rule-body forms: allow, ask, deny, authorise, cond, when, unless, if, and, or, not, positional, exact, anywhere, forbidden, flag, parameter, tail"),
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

/// Parse `(allow REASON?)`, `(ask REASON?)`, `(deny REASON?)` — the
/// surface decision verbs. Reason is an optional string.
fn parse_decision_verb(
    decision: Decision,
    args: &[Sexpr],
    span: may_i_core::Span,
) -> Result<Effect, RawError> {
    if args.len() > 1 {
        return Err(RawError::new(
            "decision verbs accept at most one optional reason string",
            span,
        ));
    }
    let reason = if args.is_empty() {
        None
    } else {
        Some(
            args[0]
                .as_atom_or_str()
                .ok_or_else(|| RawError::new("decision reason must be a string", args[0].span()))?
                .to_string(),
        )
    };
    Ok(Effect::Terminal { decision, reason })
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
                    "else branch must have exactly one rule body",
                    arg.span(),
                ));
            };
            fallback = Some(Box::new(else_effect));
            continue;
        }

        // Regular branch: (PREDICATE BODY)
        if branch_list.len() != 2 {
            return Err(RawError::new(
                "cond branch must have exactly a predicate and a rule body",
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
            "when must have exactly a predicate and a rule body: (when PREDICATE BODY)",
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
            "unless must have exactly a predicate and a rule body: (unless PREDICATE BODY)",
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
            "if must have exactly 3 arguments: (if PREDICATE THEN-BODY ELSE-BODY)",
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
/// Syntax: `(and BODY ...)` - all effects must return non-Nil
fn parse_and(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new(
            "and must have at least one rule body: (and BODY+)",
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
/// Syntax: `(or BODY ...)` - returns first non-Nil effect
fn parse_or(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.is_empty() {
        return Err(RawError::new(
            "or must have at least one rule body: (or BODY+)",
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
/// Syntax: `(not BODY)` - inverts Allow/Nil, passes through Ask/Deny
fn parse_not(args: &[Sexpr], span: may_i_core::Span) -> Result<Effect, RawError> {
    if args.len() != 1 {
        return Err(RawError::new(
            "not must have exactly one rule body: (not BODY)",
            span,
        ));
    }

    let effect = parse_effect(&args[0])?;

    Ok(Effect::Not {
        effect: Box::new(effect),
    })
}

// Tests assert one variant and `panic!`/ignore the rest; the catch-all arm is
// intentional here.
#[cfg(test)]
#[allow(clippy::wildcard_enum_match_arm)]
mod tests {
    use super::parse_effect;
    use may_i_core::Decision;
    use may_i_core::ast::Effect;
    use may_i_core::pattern::{ArgPattern, MatchMode};
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

    // ── parser-named-bindings: (authorise #var) at rule body ────────

    #[test]
    fn parse_authorise_with_binding() {
        let effect = parse_effect_str("(authorise #cmd)").unwrap();
        match effect {
            Effect::Authorise { binding, .. } => assert_eq!(binding.as_str(), "cmd"),
            other => panic!("expected Effect::Authorise, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bare_authorise_without_binding() {
        let err = parse_effect_str("(authorise)").unwrap_err();
        assert!(format!("{err}").contains("binding reference"));
    }

    #[test]
    fn rejects_authorise_with_non_binding() {
        let err = parse_effect_str("(authorise \"cmd\")").unwrap_err();
        assert!(format!("{err}").contains("binding reference"));
    }

    #[test]
    fn parse_allow_effect() {
        let effect = parse_effect_str(r#"(allow)"#).unwrap();
        match effect {
            Effect::Terminal {
                decision: Decision::Allow,
                reason,
            } => assert!(reason.is_none()),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_allow_with_reason() {
        let effect = parse_effect_str(r#"(allow "safe command")"#).unwrap();
        match effect {
            Effect::Terminal {
                decision: Decision::Allow,
                reason,
            } => assert_eq!(reason.as_deref(), Some("safe command")),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_ask_effect() {
        let effect = parse_effect_str(r#"(ask "confirm")"#).unwrap();
        match effect {
            Effect::Terminal {
                decision: Decision::Ask,
                reason,
            } => assert_eq!(reason.as_deref(), Some("confirm")),
            _ => panic!("expected Ask"),
        }
    }

    #[test]
    fn parse_deny_effect() {
        let effect = parse_effect_str(r#"(deny "dangerous")"#).unwrap();
        match effect {
            Effect::Terminal {
                decision: Decision::Deny,
                reason,
            } => assert_eq!(reason.as_deref(), Some("dangerous")),
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn legacy_may_i_form_rejected() {
        let err = parse_effect_str(r#"(may-i (positional *))"#).expect_err("expected error");
        assert!(format!("{err}").contains("(may-i …) is retired"));
    }

    #[test]
    fn legacy_effect_form_rejected() {
        let err = parse_effect_str(r#"(effect :allow)"#).expect_err("expected error");
        assert!(format!("{err}").contains("(effect :decision …) is retired"));
    }

    #[test]
    fn bare_authorise_at_effect_position_rejected() {
        let err = parse_effect_str(r#"(authorise)"#).expect_err("expected error");
        // parser-named-bindings: bare (authorise) is rejected because
        // the verb now requires a #var binding reference.
        assert!(format!("{err}").contains("binding reference"), "{err}");
    }

    #[test]
    fn parse_when_effect() {
        let effect = parse_effect_str(r#"(when (fact? :via/ssh) (allow))"#).unwrap();
        match effect {
            Effect::When { .. } => {}
            _ => panic!("expected When"),
        }
    }

    #[test]
    fn parse_unless_effect() {
        let effect = parse_effect_str(r#"(unless (fact? :dangerous) (allow))"#).unwrap();
        match effect {
            Effect::Unless { .. } => {}
            _ => panic!("expected Unless"),
        }
    }

    #[test]
    fn parse_if_effect() {
        let effect = parse_effect_str(r#"(if (fact? :via/ssh) (allow) (ask))"#).unwrap();
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
                ((fact? :via/ssh) (allow))
                ((positional "push") (ask))
                (else (deny)))
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
            Effect::ArgPattern(ArgPattern::Ordered {
                mode: MatchMode::Positional,
                ..
            }) => {}
            _ => panic!("expected ArgPattern::Positional"),
        }
    }

    #[test]
    fn parse_and_effect() {
        let effect = parse_effect_str(r#"(and (positional "push") (allow))"#).unwrap();
        match effect {
            Effect::And { effects } => {
                assert_eq!(effects.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn parse_or_effect() {
        let effect = parse_effect_str(r#"(or (positional "push") (allow))"#).unwrap();
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
                (else (deny))
                ((fact? :via/ssh) (allow)))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("last branch"));
    }

    #[test]
    fn parse_cond_without_else() {
        let effect = parse_effect_str(
            r#"
            (cond
                ((fact? :via/ssh) (allow))
                ((positional "push") (ask)))
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
                    ((positional "push") (ask))
                    (else (allow))))
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
    fn empty_effect_error() {
        let err = parse_effect_str(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty rule body"));
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
        assert!(format!("{err}").contains("a rule body must be a list or command literal"));
    }

    #[test]
    fn unknown_effect_form_error() {
        let err = parse_effect_str(r#"(unknown)"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown rule-body form"));
    }

    #[test]
    fn legacy_effect_bare_form_rejected() {
        let err = parse_effect_str(r#"(effect)"#).expect_err("expected error");
        assert!(format!("{err}").contains("(effect :decision …) is retired"));
    }

    #[test]
    fn legacy_may_i_bare_form_rejected() {
        let err = parse_effect_str(r#"(may-i)"#).expect_err("expected error");
        assert!(format!("{err}").contains("(may-i …) is retired"));
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
        let err = parse_effect_str(r#"(cond (else (allow) (deny)))"#).expect_err("expected error");
        assert!(format!("{err}").contains("else branch must have exactly one rule body"));
    }

    #[test]
    fn cond_branch_with_wrong_arg_count_error() {
        let err = parse_effect_str(r#"(cond ((fact? :via/ssh)))"#).expect_err("expected error");
        assert!(
            format!("{err}").contains("cond branch must have exactly a predicate and a rule body")
        );
    }

    #[test]
    fn when_with_wrong_arg_count_error() {
        let err = parse_effect_str(r#"(when (fact? :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("when must have exactly"));
    }

    #[test]
    fn when_with_too_many_args_error() {
        let err = parse_effect_str(r#"(when (fact? :via/ssh) (allow) (deny))"#)
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
    fn quoted_string_matching_reserved_word_is_command_literal() {
        // A quoted string like "or" should be a command literal, not parsed as the `or` keyword.
        for word in &["or", "and", "not", "if", "when", "cond", "effect", "rule"] {
            let input = format!(r#""{word}""#);
            let result = parse_effect_str(&input);
            assert!(
                result.is_ok(),
                "quoted reserved word {word:?} should parse as command literal, got: {result:?}"
            );
            match result.unwrap() {
                Effect::CommandPattern(_) => {}
                other => panic!("expected CommandPattern for {word:?}, got: {other:?}"),
            }
        }
    }

    #[test]
    fn if_with_too_many_args_error() {
        let err = parse_effect_str(r#"(if (fact? :via/ssh) (allow) (deny) (ask))"#)
            .expect_err("expected error");
        assert!(format!("{err}").contains("if must have exactly 3 arguments"));
    }
}

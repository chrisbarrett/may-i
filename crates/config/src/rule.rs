// Rule and define parser for the unified DSL.
// Syntax: (rule COMMAND EFFECT [CHECK...])

use may_i_core::ast::{Define, Rule, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a rule from an s-expression.
///
/// Syntax: `(rule COMMAND EFFECT [CHECK...])`
///
/// A rule takes exactly two positional forms: a command pattern and a single
/// body effect. Optional `(check ...)` forms may follow. Rules with zero or
/// more than one non-check body form produce a parse error.
///
/// Examples:
/// - `(rule "git" (effect :allow))` - allow all git commands
/// - `(rule "git" (and (positional "push") (effect :ask)))` - ask for git push
/// - `(rule "git" (effect :deny) (check :deny "rm -rf /"))`
/// - `(rule (or "git" "gh") (effect :allow))` - allow git or gh
pub fn parse_rule(sexpr: &Sexpr) -> Result<Spanned<Rule>, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("rule must be a list", sexpr.span()))?;

    if list.len() < 2 {
        return Err(RawError::new(
            "rule must have at least a command and an effect: (rule COMMAND EFFECT)",
            sexpr.span(),
        ));
    }

    // Parse command effect (position 1 in the list, after "rule")
    let command_effect = crate::effect::parse_effect(&list[1])?;

    // Parse all remaining items - exactly one effect plus optional checks
    let mut effects = Vec::new();
    let mut checks = Vec::new();

    for sexpr in list.iter().skip(2) {
        // Check for check forms
        if let Some(lst) = sexpr.as_list()
            && !lst.is_empty()
            && let Some(tag) = lst[0].as_atom()
            && tag == "check"
        {
            let check_items = crate::config::parse_check(&lst[1..], sexpr.span())?;
            checks.extend(check_items);
            continue;
        }

        let effect = crate::effect::parse_effect(sexpr)?;
        effects.push(effect);
    }

    if effects.is_empty() {
        return Err(RawError::new(
            "rule requires an effect: (rule COMMAND EFFECT)",
            sexpr.span(),
        ));
    }

    if effects.len() > 1 {
        return Err(RawError::new(
            "rule accepts exactly one effect, but multiple were given",
            sexpr.span(),
        )
        .with_help("wrap multiple effects with a combinator: (and ...) or (or ...)"));
    }

    let effect = effects.into_iter().next().unwrap();
    let rule = Rule::new(command_effect, effect, checks, sexpr.span());

    Ok(Spanned::new(rule, sexpr.span()))
}

/// Parse a named predicate definition from an s-expression.
///
/// Syntax: `(define NAME PREDICATE)`
///
/// Examples:
/// - `(define remote-prod (and (fact? :via/ssh) (fact? [:ssh/host (regex "^prod-")])))`
/// - `(define safe-cmd (or (positional "status") (positional "log")))`
pub fn parse_define(sexpr: &Sexpr) -> Result<Define, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("define must be a list", sexpr.span()))?;

    if list.len() != 3 {
        return Err(RawError::new(
            "define must have exactly a name and a predicate",
            sexpr.span(),
        ));
    }

    // Parse name
    let name = list[1]
        .as_atom()
        .ok_or_else(|| RawError::new("define name must be an atom", list[1].span()))?;

    // Check for reserved names
    if is_reserved_define_name(name) {
        return Err(
            RawError::new(format!("reserved predicate name: {name}"), list[1].span())
                .with_help("choose a different name"),
        );
    }

    // Parse predicate
    let predicate = crate::predicate::parse_predicate(&list[2])?;

    Ok(Define::new(
        name.to_string(),
        Spanned::new(predicate, list[2].span()),
        sexpr.span(),
    ))
}

/// Check if a name is reserved and cannot be used for defines.
fn is_reserved_define_name(name: &str) -> bool {
    matches!(
        name,
        "rule"
            | "define"
            | "fact?"
            | "and"
            | "or"
            | "not"
            | "positional"
            | "exact"
            | "anywhere"
            | "forbidden"
            | "="
            | "effect"
            | "may-i"
            | "cond"
            | "when"
            | "unless"
            | "if"
            | "else"
            | "safe-env-vars"
            | "check"
            | "wrapper"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{Define, Effect, Predicate, Rule};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use may_i_sexpr::RawError;

    fn parse_rule_str(input: &str) -> Result<Rule, RawError> {
        let (forms, errors) = may_i_sexpr::parse(input);
        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }
        if forms.len() != 1 {
            return Err(RawError::new(
                "expected exactly one form",
                Span::new(0, input.len()),
            ));
        }
        parse_rule(&forms[0]).map(|s| s.value)
    }

    fn parse_define_str(input: &str) -> Result<Define, RawError> {
        let (forms, errors) = may_i_sexpr::parse(input);
        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }
        if forms.len() != 1 {
            return Err(RawError::new(
                "expected exactly one form",
                Span::new(0, input.len()),
            ));
        }
        parse_define(&forms[0])
    }

    #[test]
    fn parse_simple_rule() {
        let rule = parse_rule_str(r#"(rule "git" (effect :allow))"#).unwrap();
        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(ref s)) if s == "git")
        );
        assert!(matches!(rule.effect.value, Effect::Allow(_)));
    }

    #[test]
    fn parse_rule_with_and_combinator() {
        let rule =
            parse_rule_str(r#"(rule "git" (and (positional "push") (effect :ask)))"#).unwrap();
        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(ref s)) if s == "git")
        );
        assert!(matches!(rule.effect.value, Effect::And { .. }));
    }

    #[test]
    fn parse_rule_with_or_command() {
        let rule = parse_rule_str(r#"(rule (or "git" "gh") (effect :allow))"#).unwrap();
        assert!(matches!(
            rule.command_effect.value,
            Effect::CommandPattern(CommandPattern::Or(_))
        ));
    }

    #[test]
    fn parse_simple_define() {
        let def = parse_define_str(
            r#"
            (define remote-prod (and (fact? :via/ssh) (fact? [:ssh/host "prod-1"])))
        "#,
        )
        .unwrap();
        assert_eq!(def.name, "remote-prod");
        assert!(matches!(def.predicate.value, Predicate::And(_)));
    }

    #[test]
    fn reserved_name_is_error() {
        let err =
            parse_define_str(r#"(define fact? (fact? :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("reserved"));
    }

    #[test]
    fn rule_with_no_effect_is_error() {
        let err = parse_rule_str(r#"(rule "git")"#).expect_err("expected error");
        assert!(format!("{err}").contains("requires an effect"));
    }

    #[test]
    fn parse_rule_with_when_effect() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (when (fact? :via/ssh) (effect :allow)))
        "#,
        )
        .unwrap();
        assert!(matches!(rule.effect.value, Effect::When { .. }));
    }

    #[test]
    fn parse_rule_with_cond_effect() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (cond
                    ((positional "status") (effect :allow))
                    ((positional "push") (effect :ask))
                    (else (effect :deny))))
        "#,
        )
        .unwrap();
        assert!(matches!(rule.effect.value, Effect::Cond { .. }));
    }

    #[test]
    fn parse_define_with_named_reference() {
        let def = parse_define_str(
            r#"
            (define complex
                (and safe-git (fact? :via/ssh)))
        "#,
        )
        .unwrap();
        match &def.predicate.value {
            Predicate::And(preds) => {
                assert_eq!(preds.len(), 2);
                assert!(matches!(preds[0], Predicate::Named(_)));
                assert!(matches!(preds[1], Predicate::Fact(_)));
            }
            _ => panic!("expected And with Named reference"),
        }
    }

    #[test]
    fn multiple_effects_are_error() {
        let err = parse_rule_str(r#"(rule "git" (effect :allow) (effect :deny))"#)
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("exactly one effect"));
        assert!(err.help.as_deref().unwrap_or("").contains("combinator"));
    }

    #[test]
    fn parse_rule_too_few_elements_error() {
        let err = parse_rule_str(r#"(rule)"#).expect_err("expected error");
        assert!(format!("{err}").contains("must have at least a command"));
    }

    #[test]
    fn parse_define_wrong_arity_error() {
        let err = parse_define_str(r#"(define foo)"#).expect_err("expected error");
        assert!(format!("{err}").contains("must have exactly a name and a predicate"));
    }

    #[test]
    fn parse_rule_with_check_alongside_effect() {
        let rule =
            parse_rule_str(r#"(rule "git" (effect :allow) (check :allow "git status"))"#).unwrap();
        assert!(matches!(rule.effect.value, Effect::Allow(_)));
        assert_eq!(rule.checks.len(), 1);
    }
}

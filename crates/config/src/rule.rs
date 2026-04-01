// Rule and define parser for the unified DSL.
// Syntax: (rule COMMAND-EFFECT EFFECT... [CHECK...])

use may_i_core::ast::{Define, Effect, Rule, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a rule from an s-expression.
///
/// New unified syntax: `(rule COMMAND-EFFECT EFFECT... [CHECK...])`
///
/// Effects are evaluated in order. Pattern effects return Allow on match or Nil.
/// Terminal effects return a decision. The evaluator applies (or ... (effect :ask))
/// at the top level, so rules default to :ask if no terminal effect is reached.
///
/// Checks can be included inline: `(check :allow "cmd")` or `(check (with-facts ...) ...)`
///
/// Examples:
/// - `(rule "git" (effect :allow))` - allow all git commands
/// - `(rule "git" (positional "push") (effect :ask))` - ask for git push
/// - `(rule "git" (effect :deny) (check :deny "rm -rf /"))`
/// - `(rule (or "git" "gh") (effect :allow))` - allow git or gh
/// - `(rule "ssh" (positional [:host *] . (may-i *)) (effect :deny))`
pub fn parse_rule(sexpr: &Sexpr) -> Result<Spanned<Rule>, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("rule must be a list", sexpr.span()))?;

    if list.len() < 2 {
        return Err(RawError::new(
            "rule must have at least a command effect: (rule COMMAND)",
            sexpr.span(),
        ));
    }

    // Parse command effect (position 1 in the list, after "rule")
    // This can be a command literal, command pattern, or effect
    let command_effect = crate::effect::parse_effect(&list[1])?;

    // Parse all remaining items - effects and checks
    let mut effects = Vec::new();
    let mut checks = Vec::new();

    for sexpr in list.iter().skip(2) {
        // Skip :effect keyword (for backward compatibility during migration)
        if let Some(atom) = sexpr.as_atom()
            && atom == ":effect"
        {
            continue;
        }

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

    let rule = Rule::new(command_effect, effects, checks, sexpr.span());

    Ok(Spanned::new(rule, sexpr.span()))
}

/// Parse shorthand effect notation.
/// - `:allow` -> `(effect :allow)`
/// - `:ask` -> `(effect :ask)`
/// - `:deny` -> `(effect :deny)`
/// - `[:ask "reason"]` -> `(effect :ask "reason")`
pub fn parse_shorthand_effect(sexpr: &Sexpr) -> Result<Effect, RawError> {
    // Handle keyword shorthand: :allow, :ask, :deny
    if let Some(atom) = sexpr.as_atom() {
        return match atom {
            ":allow" => Ok(Effect::Allow(None)),
            ":ask" => Ok(Effect::Ask(None)),
            ":deny" => Ok(Effect::Deny(None)),
            _ => Err(RawError::new(
                format!("unknown shorthand effect keyword: {}", atom),
                sexpr.span(),
            )),
        };
    }

    // Handle vector shorthand: [:ask "reason"] or [:allow]
    if let Sexpr::Vector(items, _) = sexpr {
        if items.is_empty() {
            return Err(RawError::new(
                "effect vector shorthand cannot be empty",
                sexpr.span(),
            ));
        }

        let kw = items[0]
            .as_atom()
            .ok_or_else(|| RawError::new("effect keyword must be an atom", items[0].span()))?;

        let reason = if items.len() > 1 {
            Some(
                items[1]
                    .as_atom()
                    .ok_or_else(|| {
                        RawError::new("effect reason must be a string", items[1].span())
                    })?
                    .to_string(),
            )
        } else {
            None
        };

        return match kw {
            ":allow" => Ok(Effect::Allow(reason)),
            ":ask" => Ok(Effect::Ask(reason)),
            ":deny" => Ok(Effect::Deny(reason)),
            other => Err(RawError::new(
                format!("unknown effect keyword: {}", other),
                items[0].span(),
            )),
        };
    }

    Err(RawError::new(
        "shorthand effect must be a keyword (:allow/:ask/:deny) or a vector [:keyword \"reason\"]",
        sexpr.span(),
    ))
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
    use crate::*;
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

    fn parse_shorthand_str(input: &str) -> Result<Effect, RawError> {
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
        parse_shorthand_effect(&forms[0])
    }

    #[test]
    fn parse_simple_rule() {
        let rule = parse_rule_str(r#"(rule "git" (effect :allow))"#).unwrap();
        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(ref s)) if s == "git")
        );
        assert_eq!(rule.effects.len(), 1);
        assert!(matches!(rule.effects[0].value, Effect::Allow(_)));
    }

    #[test]
    fn parse_rule_with_effects() {
        let rule = parse_rule_str(r#"(rule "git" (positional "push") (effect :ask))"#).unwrap();
        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(ref s)) if s == "git")
        );
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0].value, Effect::ArgPattern(_)));
        assert!(matches!(rule.effects[1].value, Effect::Ask(_)));
    }

    #[test]
    fn parse_rule_with_multiple_effects() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (positional "push")
                (when (fact? :via/ssh) (effect :allow))
                (effect :deny))
        "#,
        )
        .unwrap();
        assert_eq!(rule.effects.len(), 3);
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
    fn parse_rule_with_shorthand_effect() {
        // Using shorthand :allow syntax
        let rule = parse_rule_str(r#"(rule "git" :allow)"#).unwrap();
        assert_eq!(rule.effects.len(), 1);
        assert!(matches!(rule.effects[0].value, Effect::Allow(_)));
    }

    #[test]
    fn parse_rule_with_vector_shorthand() {
        // Using vector shorthand [:ask "reason"]
        let rule = parse_rule_str(r#"(rule "git" [:ask "confirm"])"#).unwrap();
        assert_eq!(rule.effects.len(), 1);
        match &rule.effects[0].value {
            Effect::Ask(Some(reason)) => assert_eq!(reason, "confirm"),
            _ => panic!("expected Ask with reason"),
        }
    }

    #[test]
    fn parse_shorthand_keyword() {
        let effect = parse_shorthand_str(r#":allow"#).unwrap();
        assert!(matches!(effect, Effect::Allow(None)));

        let effect = parse_shorthand_str(r#":ask"#).unwrap();
        assert!(matches!(effect, Effect::Ask(None)));

        let effect = parse_shorthand_str(r#":deny"#).unwrap();
        assert!(matches!(effect, Effect::Deny(None)));
    }

    #[test]
    fn parse_shorthand_vector() {
        let effect = parse_shorthand_str(r#"[:allow]"#).unwrap();
        assert!(matches!(effect, Effect::Allow(None)));

        let effect = parse_shorthand_str(r#"[:ask "confirm"]"#).unwrap();
        assert!(matches!(effect, Effect::Ask(Some(ref s)) if s == "confirm"));
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
    fn rule_with_just_command_is_valid() {
        // A rule with just a command is valid - it defaults to :ask
        let rule = parse_rule_str(r#"(rule "git")"#).unwrap();
        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(ref s)) if s == "git")
        );
        assert!(rule.effects.is_empty());
    }

    #[test]
    fn rule_with_effects_no_default() {
        let rule = parse_rule_str(r#"(rule "git" (positional "push"))"#).unwrap();
        // Effects are now in the effects vector, no separate default_effect
        assert_eq!(rule.effects.len(), 1);
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
        assert_eq!(rule.effects.len(), 1);
        assert!(matches!(rule.effects[0].value, Effect::When { .. }));
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
        assert_eq!(rule.effects.len(), 1);
        assert!(matches!(rule.effects[0].value, Effect::Cond { .. }));
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
    fn effect_keyword_is_skipped() {
        // :effect keyword is now skipped during parsing (backward compatibility)
        let rule = parse_rule_str(r#"(rule "git" :effect (effect :allow))"#).unwrap();
        assert_eq!(rule.effects.len(), 1);
        assert!(matches!(rule.effects[0].value, Effect::Allow(_)));
    }

    #[test]
    fn multiple_effects_are_allowed() {
        // Multiple effects are now allowed in the effects vector
        let rule = parse_rule_str(r#"(rule "git" (effect :allow) (effect :deny))"#).unwrap();
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0].value, Effect::Allow(_)));
        assert!(matches!(rule.effects[1].value, Effect::Deny(_)));
    }

    #[test]
    fn parse_rule_too_few_elements_error() {
        let err = parse_rule_str(r#"(rule)"#).expect_err("expected error");
        assert!(format!("{err}").contains("must have at least a command"));
    }

    #[test]
    fn parse_shorthand_unknown_keyword_error() {
        let err = parse_shorthand_str(r#":foo"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown shorthand effect keyword"));
    }

    #[test]
    fn parse_shorthand_empty_vector_error() {
        let err = parse_shorthand_str(r#"[]"#).expect_err("expected error");
        assert!(format!("{err}").contains("cannot be empty"));
    }

    #[test]
    fn parse_shorthand_unknown_vector_keyword_error() {
        let err = parse_shorthand_str(r#"[:foo "reason"]"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown effect keyword"));
    }

    #[test]
    fn parse_shorthand_invalid_form_error() {
        let err = parse_shorthand_str(r#"("not" "valid")"#).expect_err("expected error");
        assert!(format!("{err}").contains("shorthand effect must be"));
    }

    #[test]
    fn parse_define_wrong_arity_error() {
        let err = parse_define_str(r#"(define foo)"#).expect_err("expected error");
        assert!(format!("{err}").contains("must have exactly a name and a predicate"));
    }
}

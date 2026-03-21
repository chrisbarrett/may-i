// Rule and define parser for v2 DSL.
// Task 2.8: Implement rule parser with simplified syntax
// Task 2.9: Implement define parser for named predicates

use may_i_core::v2::ast::{Define, Rule, Spanned};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a rule from an s-expression.
///
/// Syntax: `(rule COMMAND-PATTERN PREDICATE* EFFECT)`
///
/// Examples:
/// - `(rule "git" (effect :allow))` - allow all git commands
/// - `(rule "git" (positional "push") (effect :ask))` - ask for git push
/// - `(rule "git" (and (has :via/ssh) (positional "push")) (effect :allow))`
/// - `(rule (or "git" "gh") (effect :allow))` - allow git or gh
pub fn parse_rule(sexpr: &Sexpr) -> Result<Spanned<Rule>, RawError> {
    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("rule must be a list", sexpr.span()))?;

    if list.len() < 2 {
        return Err(RawError::new(
            "rule must have at least a command pattern and an effect",
            sexpr.span(),
        ));
    }

    // Parse command pattern (position 1 in the list, after "rule")
    let command = super::command::parse_command_pattern(&list[1])?;
    let command_spanned = Spanned::new(command, list[1].span());

    // Parse predicates (all but the last element)
    let mut predicates = Vec::new();
    let effect_idx = list.len() - 1;

    for predicate_sexpr in list.iter().take(effect_idx).skip(2) {
        let predicate = super::predicate::parse_predicate(predicate_sexpr)?;
        predicates.push(Spanned::new(predicate, predicate_sexpr.span()));
    }

    // Parse effect (last element)
    let effect = super::effect::parse_effect(&list[effect_idx])?;

    let rule = Rule::new(command_spanned, predicates, effect, sexpr.span());

    Ok(Spanned::new(rule, sexpr.span()))
}

/// Parse a named predicate definition from an s-expression.
///
/// Syntax: `(define NAME PREDICATE)`
///
/// Examples:
/// - `(define remote-prod (and (has :via/ssh) (has [:ssh/host (regex "^prod-")])))`
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
    let predicate = super::predicate::parse_predicate(&list[2])?;

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
            | "has"
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
            | "case"
            | "when"
            | "unless"
            | "if"
            | "safe-env-vars"
            | "check"
            | "wrapper"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::span::Span;
    use may_i_core::v2::ast::Effect;
    use may_i_core::v2::pattern::CommandPattern;
    use may_i_core::v2::predicate::Predicate;

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
        assert!(matches!(rule.command.value, CommandPattern::Literal(ref s) if s == "git"));
        assert!(rule.predicates.is_empty());
        assert!(rule.effect.value.is_terminal());
    }

    #[test]
    fn parse_rule_with_predicate() {
        let rule = parse_rule_str(r#"(rule "git" (positional "push") (effect :ask))"#).unwrap();
        assert!(matches!(rule.command.value, CommandPattern::Literal(ref s) if s == "git"));
        assert_eq!(rule.predicates.len(), 1);
        assert!(matches!(rule.predicates[0].value, Predicate::Arg(_)));
    }

    #[test]
    fn parse_rule_with_multiple_predicates() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (has :via/ssh)
                (positional "push")
                (effect :allow))
        "#,
        )
        .unwrap();
        assert_eq!(rule.predicates.len(), 2);
    }

    #[test]
    fn parse_rule_with_or_command() {
        let rule = parse_rule_str(r#"(rule (or "git" "gh") (effect :allow))"#).unwrap();
        assert!(matches!(rule.command.value, CommandPattern::Or(_)));
    }

    #[test]
    fn parse_simple_define() {
        let def = parse_define_str(
            r#"
            (define remote-prod (and (has :via/ssh) (has [:ssh/host "prod-1"])))
        "#,
        )
        .unwrap();
        assert_eq!(def.name, "remote-prod");
        assert!(matches!(def.predicate.value, Predicate::And(_)));
    }

    #[test]
    fn reserved_name_is_error() {
        let err = parse_define_str(r#"(define has (has :via/ssh))"#).expect_err("expected error");
        assert!(format!("{err}").contains("reserved"));
    }

    #[test]
    fn rule_without_enough_args_is_error() {
        let err = parse_rule_str(r#"(rule "git")"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect must be a list"));
    }

    #[test]
    fn parse_rule_with_regex_command() {
        let rule = parse_rule_str(r#"(rule (regex "^git") (effect :allow))"#).unwrap();
        assert!(matches!(rule.command.value, CommandPattern::Regex(_)));
    }

    #[test]
    fn parse_rule_with_complex_predicates() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (and
                    (has :via/ssh)
                    (or (positional "push") (positional "pull")))
                (effect :ask))
        "#,
        )
        .unwrap();
        assert_eq!(rule.predicates.len(), 1);
        match &rule.predicates[0].value {
            Predicate::And(preds) => assert_eq!(preds.len(), 2),
            _ => panic!("expected And predicate"),
        }
    }

    #[test]
    fn parse_rule_with_when_effect() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (when (has :via/ssh) (effect :allow)))
        "#,
        )
        .unwrap();
        assert!(matches!(rule.effect.value, Effect::When { .. }));
    }

    #[test]
    fn parse_rule_with_case_effect() {
        let rule = parse_rule_str(
            r#"
            (rule "git"
                (case
                    [(positional "status") (effect :allow)]
                    [(positional "push") (effect :ask)]
                    [else (effect :deny)]))
        "#,
        )
        .unwrap();
        assert!(matches!(rule.effect.value, Effect::Case { .. }));
    }

    #[test]
    fn parse_define_with_named_reference() {
        let def = parse_define_str(
            r#"
            (define complex
                (and safe-git (has :via/ssh)))
        "#,
        )
        .unwrap();
        match &def.predicate.value {
            Predicate::And(preds) => {
                assert_eq!(preds.len(), 2);
                assert!(matches!(preds[0], Predicate::Named(_)));
                assert!(matches!(preds[1], Predicate::Has(_)));
            }
            _ => panic!("expected And with Named reference"),
        }
    }

    #[test]
    fn invalid_rule_missing_effect_is_error() {
        // (invalid "form") is parsed as a rule with "invalid" as command and "form" as predicate
        // but it's missing the required effect
        let err = parse_rule_str(r#"(invalid "form")"#).expect_err("expected error");
        assert!(format!("{err}").contains("effect"));
    }
}

// Config parser for the unified DSL.
// Task 2.10: Implement safe-env-vars and check parsers (preserve existing behavior)

use may_i_core::Span;
use may_i_core::ast::{Check, Config, SecurityConfig};
use may_i_core::{ContextFacts, Decision, Keyword};
use may_i_sexpr::{RawError, Sexpr};

/// Parse a config from an s-expression string.
pub fn parse_config(input: &str) -> Result<Config, RawError> {
    let (forms, errors) = may_i_sexpr::parse(input);
    if let Some(err) = errors.into_iter().next() {
        return Err(err);
    }

    let mut config = parse_config_from_sexprs(&forms)?;
    config.source_text = Some(input.to_string());
    Ok(config)
}

/// Parse a config from pre-parsed Sexpr forms.
///
/// This enables parsing from migrated CST forms that have been converted to
/// Sexpr, without re-serializing to text.
pub fn parse_config_from_sexprs(forms: &[Sexpr]) -> Result<Config, RawError> {
    let mut config = Config::default();

    for form in forms {
        let list = form
            .as_list()
            .ok_or_else(|| RawError::new("top-level form must be a list", form.span()))?;

        if list.is_empty() {
            return Err(RawError::new("empty top-level form", form.span()));
        }

        let tag = list[0]
            .as_atom()
            .ok_or_else(|| RawError::new("form tag must be an atom", list[0].span()))?;

        match tag {
            "rule" => {
                let rule = crate::rule::parse_rule(form)?;
                config.rules.push(rule.value);
            }
            "define" => {
                let define = crate::rule::parse_define(form)?;
                config.defines.push(define);
            }
            "safe-env-vars" => {
                parse_safe_env_vars(&list[1..], &mut config.security, form.span())?;
            }
            "check" => {
                let checks = parse_check(&list[1..], form.span())?;
                config.checks.extend(checks);
            }
            other => {
                return Err(RawError::new(
                    format!("unknown top-level form: {other}"),
                    list[0].span(),
                )
                .with_help("valid top-level forms: rule, define, safe-env-vars, check"));
            }
        }
    }

    Ok(config)
}

/// Parse safe-env-vars form: (safe-env-vars "VAR1" "VAR2" ...)
fn parse_safe_env_vars(
    args: &[Sexpr],
    security: &mut SecurityConfig,
    _span: Span,
) -> Result<(), RawError> {
    for item in args {
        let s = item
            .as_atom_or_str()
            .ok_or_else(|| RawError::new("safe-env-vars entry must be a string", item.span()))?;
        security.safe_env_vars.insert(s.to_string());
    }
    Ok(())
}

/// Parse check form: (check DECISION "cmd" ...)
/// Supports nested with-facts: (check (with-facts [[:key]] :allow "cmd"))
pub fn parse_check(args: &[Sexpr], check_span: Span) -> Result<Vec<Check>, RawError> {
    let mut checks = Vec::new();
    let mut i = 0;

    while i < args.len() {
        // Check for with-facts wrapper
        if let Some(list) = args[i].as_list()
            && let Some("with-facts") = list.first().and_then(Sexpr::as_atom)
        {
            let with_facts_checks = parse_with_facts(list, &ContextFacts::default(), check_span)?;
            checks.extend(with_facts_checks);
            i += 1;
            continue;
        }

        // Parse decision keyword
        let expected = match args[i].as_atom().ok_or_else(|| {
            RawError::new(
                "check entries must start with a decision keyword (:allow, :deny, :ask) or with-facts",
                args[i].span(),
            )
        })? {
            ":allow" => Decision::Allow,
            ":deny" => Decision::Deny,
            ":ask" => Decision::Ask,
            other => {
                return Err(RawError::new(
                    format!("unknown expected decision: {other}"),
                    args[i].span(),
                )
                .with_help("valid decisions: :allow, :deny, :ask"));
            }
        };
        i += 1;

        // Parse command
        if i >= args.len() {
            return Err(RawError::new(
                "check must provide a command after each decision",
                check_span,
            )
            .with_help("use :allow \"cmd\" or (with-facts [[:key]] :allow \"cmd\")"));
        }

        let cmd = args[i]
            .as_atom_or_str()
            .ok_or_else(|| RawError::new("check command must be a string", args[i].span()))?;

        checks.push(Check {
            command: cmd.to_string(),
            expected,
            context: ContextFacts::default(),
            span: args[i].span(),
        });
        i += 1;
    }

    Ok(checks)
}

/// Parse with-facts form: (with-facts [[:key] [:key "value"]] :allow "cmd" ...)
fn parse_with_facts(
    list: &[Sexpr],
    inherited: &ContextFacts,
    check_span: Span,
) -> Result<Vec<Check>, RawError> {
    if list.len() < 2 {
        return Err(RawError::new(
            "with-facts must have a fact vector",
            list.first().map_or(Span::new(0, 0), Sexpr::span),
        )
        .with_help("use (with-facts [[:client/opencode]] :allow \"cmd\")"));
    }

    let facts = parse_fact_literal(&list[1])?;
    let merged = inherited.merge(&facts);

    // Parse remaining check items with merged context
    parse_check_items(&list[2..], &merged, check_span)
}

/// Parse fact literal vector: [[:key] [:key "value"]]
fn parse_fact_literal(sexpr: &Sexpr) -> Result<ContextFacts, RawError> {
    let items = match sexpr {
        Sexpr::Vector(items, _) => items,
        _ => {
            return Err(RawError::new(
                "with-facts requires a fact vector",
                sexpr.span(),
            ));
        }
    };

    let mut facts = ContextFacts::default();
    for item in items {
        let (key, value) = parse_fact_entry(item)?;
        if facts.has(&key) {
            return Err(RawError::new(
                format!("duplicate fact key in with-facts: {key}"),
                item.span(),
            ));
        }
        match value {
            Some(value) => facts.insert_scalar(key, value),
            None => facts.insert_present(key),
        }
    }

    Ok(facts)
}

/// Parse a single fact entry: [:key] or [:key "value"]
fn parse_fact_entry(entry: &Sexpr) -> Result<(Keyword, Option<String>), RawError> {
    let items = match entry {
        Sexpr::Vector(items, _) => items,
        _ => {
            return Err(RawError::new(
                "fact entries must be vectors like [:key] or [:key \"value\"]",
                entry.span(),
            ));
        }
    };

    if items.is_empty() || items.len() > 2 {
        return Err(RawError::new(
            "fact entries must have exactly a key or a key and value",
            entry.span(),
        ));
    }

    let key = parse_context_key(&items[0])?;
    let value = if items.len() == 2 {
        Some(
            items[1]
                .as_atom_or_str()
                .ok_or_else(|| {
                    RawError::new("context fact value must be a string", items[1].span())
                })?
                .to_string(),
        )
    } else {
        None
    };

    Ok((key, value))
}

/// Parse a context key (namespaced atom starting with ':').
fn parse_context_key(sexpr: &Sexpr) -> Result<Keyword, RawError> {
    let key = sexpr
        .as_atom()
        .ok_or_else(|| RawError::new("context fact key must be an atom", sexpr.span()))?;

    Keyword::new(key).map_err(|_| {
        RawError::new(
            format!("context fact key must be namespaced: {key}"),
            sexpr.span(),
        )
        .with_help("use a namespaced key like :via/ssh or :claude-code/permission-mode")
    })
}

/// Parse check items with a given context.
fn parse_check_items(
    items: &[Sexpr],
    context: &ContextFacts,
    check_span: Span,
) -> Result<Vec<Check>, RawError> {
    let mut checks = Vec::new();
    let mut i = 0;

    while i < items.len() {
        // Check for nested with-facts
        if let Some(list) = items[i].as_list()
            && let Some("with-facts") = list.first().and_then(Sexpr::as_atom)
        {
            let nested_checks = parse_with_facts(list, context, check_span)?;
            checks.extend(nested_checks);
            i += 1;
            continue;
        }

        // Parse decision
        let expected = match items[i].as_atom().ok_or_else(|| {
            RawError::new(
                "check entries must start with a decision keyword or with-facts",
                items[i].span(),
            )
        })? {
            ":allow" => Decision::Allow,
            ":deny" => Decision::Deny,
            ":ask" => Decision::Ask,
            other => {
                return Err(RawError::new(
                    format!("unknown expected decision: {other}"),
                    items[i].span(),
                )
                .with_help("valid decisions: :allow, :deny, :ask"));
            }
        };
        i += 1;

        // Parse command
        if i >= items.len() {
            return Err(RawError::new(
                "check must provide a command after each decision",
                check_span,
            ));
        }

        let cmd = items[i]
            .as_atom_or_str()
            .ok_or_else(|| RawError::new("check command must be a string", items[i].span()))?;

        checks.push(Check {
            command: cmd.to_string(),
            expected,
            context: context.clone(),
            span: items[i].span(),
        });
        i += 1;
    }

    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Decision;

    #[test]
    fn parse_empty_config() {
        let config = parse_config("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.defines.is_empty());
        assert!(config.security.safe_env_vars.is_empty());
        assert!(config.checks.is_empty());
    }

    #[test]
    fn parse_safe_env_vars() {
        let config = parse_config(r#"(safe-env-vars "HOME" "USER" "PATH")"#).unwrap();
        assert!(config.security.safe_env_vars.contains("HOME"));
        assert!(config.security.safe_env_vars.contains("USER"));
        assert!(config.security.safe_env_vars.contains("PATH"));
        assert_eq!(config.security.safe_env_vars.len(), 3);
    }

    #[test]
    fn parse_simple_check() {
        let config = parse_config(r#"(check :allow "git status" :deny "rm -rf /")"#).unwrap();
        assert_eq!(config.checks.len(), 2);
        assert_eq!(config.checks[0].command, "git status");
        assert!(matches!(config.checks[0].expected, Decision::Allow));
        assert_eq!(config.checks[1].command, "rm -rf /");
        assert!(matches!(config.checks[1].expected, Decision::Deny));
    }

    #[test]
    fn parse_check_with_ask() {
        let config = parse_config(r#"(check :ask "ssh prod-server")"#).unwrap();
        assert_eq!(config.checks.len(), 1);
        assert!(matches!(config.checks[0].expected, Decision::Ask));
    }

    #[test]
    fn parse_check_with_with_facts() {
        let config = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode] [:via/ssh]]
                    :allow "git push"))
        "#,
        )
        .unwrap();
        assert_eq!(config.checks.len(), 1);
        assert!(
            config.checks[0]
                .context
                .has(&Keyword::new(":client/opencode").unwrap())
        );
        assert!(
            config.checks[0]
                .context
                .has(&Keyword::new(":via/ssh").unwrap())
        );
    }

    #[test]
    fn parse_nested_with_facts() {
        let config = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    (with-facts [[:via/ssh]]
                        :allow "git push")))
        "#,
        )
        .unwrap();
        assert_eq!(config.checks.len(), 1);
        assert!(
            config.checks[0]
                .context
                .has(&Keyword::new(":client/opencode").unwrap())
        );
        assert!(
            config.checks[0]
                .context
                .has(&Keyword::new(":via/ssh").unwrap())
        );
    }

    #[test]
    fn parse_check_with_fact_values() {
        let config = parse_config(
            r#"
            (check
                (with-facts [[:opencode/agent "build"]]
                    :allow "npm install"))
        "#,
        )
        .unwrap();
        assert_eq!(config.checks.len(), 1);
        // The context should have the scalar value
        assert!(
            config.checks[0]
                .context
                .has(&Keyword::new(":opencode/agent").unwrap())
        );
    }

    #[test]
    fn safe_env_vars_accepts_strings() {
        // Atoms are strings in sexpr, so "123" is a valid env var name
        let config = parse_config(r#"(safe-env-vars "123" "HOME")"#).unwrap();
        assert!(config.security.safe_env_vars.contains("123"));
        assert!(config.security.safe_env_vars.contains("HOME"));
    }

    #[test]
    fn check_rejects_invalid_decision() {
        let err = parse_config(r#"(check :invalid "cmd")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown expected decision"));
    }

    #[test]
    fn check_accepts_string_commands() {
        // Atoms are strings in sexpr
        let config = parse_config(r#"(check :allow "git status" :deny "rm")"#).unwrap();
        assert_eq!(config.checks.len(), 2);
        assert_eq!(config.checks[0].command, "git status");
        assert_eq!(config.checks[1].command, "rm");
    }

    #[test]
    fn check_requires_command_after_decision() {
        let err = parse_config(r#"(check :allow)"#).expect_err("expected error");
        assert!(format!("{err}").contains("provide a command"));
    }

    #[test]
    fn duplicate_fact_key_is_error() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode] [:client/opencode]]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("duplicate fact key"));
    }

    #[test]
    fn fact_key_must_be_namespaced() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[invalid-key]]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("namespaced"));
    }

    #[test]
    fn full_config_example() {
        // Note: named predicate references (like 'safe-git) are not yet implemented
        // They will be implemented in task 3.x (define resolution)
        let config = parse_config(
            r#"
            (safe-env-vars "HOME" "USER")
            
            (define safe-git
                (or (positional "status") (positional "log")))
            
            (rule "git" (and (or (positional "status") (positional "log")) (effect :allow)))
            (rule "git" (and (positional "push") (effect :ask)))
            
            (check
                :allow "git status"
                (with-facts [[:client/opencode]] :allow "git push")
                :deny "rm -rf /")
        "#,
        )
        .unwrap();

        assert_eq!(config.security.safe_env_vars.len(), 2);
        assert_eq!(config.defines.len(), 1);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.checks.len(), 3);
    }

    // --- Error handling tests for uncovered lines ---

    #[test]
    fn parse_config_with_parse_error() {
        let err = parse_config("(") // Unclosed paren
            .expect_err("expected error");
        // The error could be various things, just verify it fails
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn parse_config_empty_top_level_form() {
        let err = parse_config("()").expect_err("expected error");
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn parse_config_non_list_top_level() {
        let err = parse_config("atom").expect_err("expected error");
        assert!(format!("{err}").contains("top-level form must be a list"));
    }

    #[test]
    fn parse_config_non_atom_tag() {
        let err = parse_config("((not-an-atom))").expect_err("expected error");
        assert!(format!("{err}").contains("form tag must be an atom"));
    }

    #[test]
    fn parse_config_unknown_form() {
        let err = parse_config("(unknown-form)").expect_err("expected error");
        assert!(format!("{err}").contains("unknown top-level form"));
    }

    #[test]
    fn safe_env_vars_non_atom() {
        let err = parse_config(r#"(safe-env-vars (not-a-string))"#).expect_err("expected error");
        assert!(format!("{err}").contains("safe-env-vars entry must be a string"));
    }

    #[test]
    fn check_invalid_decision_in_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    :invalid "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("unknown expected decision"));
    }

    #[test]
    fn check_missing_command_in_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    :allow))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("provide a command"));
    }

    #[test]
    fn check_non_atom_command_in_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    :allow (not-a-string)))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("check command must be a string"));
    }

    #[test]
    fn parse_with_facts_missing_fact_vector() {
        let err = parse_config(
            r#"
            (check
                (with-facts))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("fact vector"));
    }

    #[test]
    fn parse_fact_entry_not_vector() {
        let err = parse_config(
            r#"
            (check
                (with-facts [not-a-vector]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("fact entries must be vectors"));
    }

    #[test]
    fn parse_fact_entry_empty_vector() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[]]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("fact entries must have exactly"));
    }

    #[test]
    fn parse_fact_entry_too_many_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:key "value" "extra"]]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("fact entries must have exactly"));
    }

    #[test]
    fn parse_fact_value_not_string() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:key (not-a-string)]]
                    :allow "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("context fact value must be a string"));
    }

    #[test]
    fn parse_check_items_non_atom_decision() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    (not-an-atom) "cmd"))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("decision keyword"));
    }

    #[test]
    fn parse_check_non_atom_decision() {
        let err = parse_config(r#"(check ("not-an-atom") "cmd")"#).expect_err("expected error");
        assert!(format!("{err}").contains("check entries must start with a decision keyword"));
    }

    #[test]
    fn parse_check_with_non_list_with_facts() {
        let err = parse_config(r#"(check (with-facts :not-a-list))"#).expect_err("expected error");
        assert!(format!("{err}").contains("with-facts requires a fact vector"));
    }
}

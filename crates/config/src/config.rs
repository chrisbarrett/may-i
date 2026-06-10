// Config parser for the unified DSL.

use may_i_core::Span;
use may_i_core::ast::{AuditConfig, AuditThreshold, Check, Config, Provenance, SecurityConfig};
use may_i_core::{ContextFacts, Decision, Keyword};
use may_i_sexpr::{RawError, Sexpr};

fn parse_decision_tag(atom: &str, span: Span) -> Result<Decision, RawError> {
    match atom {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        "ask" => Ok(Decision::Ask),
        other => Err(
            RawError::new(format!("unknown decision tag: {other}"), span)
                .with_help("valid decisions: allow, ask, deny"),
        ),
    }
}

/// Parse a config from an s-expression string.
#[must_use = "parsed config should be used"]
pub fn parse_config(input: &str) -> Result<Config, RawError> {
    let (forms, errors) = may_i_sexpr::parse(input);
    if let Some(err) = errors.into_iter().next() {
        return Err(err);
    }

    parse_config_from_sexprs(&forms)
}

/// Parse a config from pre-parsed Sexpr forms.
///
/// This enables parsing from migrated CST forms that have been converted to
/// Sexpr, without re-serializing to text.
#[must_use = "parsed config should be used"]
pub fn parse_config_from_sexprs(forms: &[Sexpr]) -> Result<Config, RawError> {
    let mut config = Config::default();
    config
        .style_specs
        .extend(crate::prelude::prelude_style_specs());
    config.parsers.extend(crate::prelude::prelude_parsers());

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
            "audit" => {
                config.audit = parse_audit_form(list, form.span())?;
            }
            "define-arg-style" => {
                let spec = crate::style::parse_style_definition(form)?;
                push_style_spec(&mut config, spec);
            }
            "parser" => {
                let parser = crate::parser_form::parse_parser_form(form)?;
                push_parser(&mut config, parser);
            }
            "load" => {
                return Err(RawError::new(
                    "load forms should be resolved before parsing",
                    list[0].span(),
                )
                .with_help(
                    "this is an internal error — load expansion should happen in the IO layer",
                ));
            }
            other => {
                return Err(RawError::new(
                    format!("unknown top-level form: {other}"),
                    list[0].span(),
                )
                .with_help(
                    "valid top-level forms: rule, define, safe-env-vars, check, audit, define-arg-style, parser",
                ));
            }
        }
    }

    Ok(config)
}

/// Push a `Parser` onto config, warning on duplicates by program. User
/// declarations that shadow a prelude-shipped parser are silent — the
/// prelude is the binary's default that the user is expected to be able
/// to override.
fn push_parser(config: &mut Config, parser: may_i_core::ast::Parser) {
    let existing_non_prelude = config
        .parsers
        .iter()
        .any(|p| p.program == parser.program && !p.provenance.is_prelude());
    if existing_non_prelude {
        eprintln!(
            "warning: duplicate (parser \"{}\" …) — last declaration wins",
            parser.program
        );
    }
    config.parsers.push(parser);
}

/// Push a `StyleSpec` onto config, warning on duplicates by name.
fn push_style_spec(config: &mut Config, spec: may_i_core::ast::StyleSpec) {
    if config.style_specs.iter().any(|s| s.name == spec.name) {
        eprintln!(
            "warning: duplicate define-arg-style for `{}` — last declaration wins",
            spec.name
        );
    }
    config.style_specs.push(spec);
}

/// Parse a config from sexprs tagged with provenance.
///
/// Each sexpr is paired with a `Provenance` value that gets applied to the
/// resulting `Rule` or `Define`.
#[must_use = "parsed config should be used"]
pub(crate) fn parse_config_from_tagged_sexprs(
    forms: &[(Sexpr, Provenance)],
) -> Result<Config, RawError> {
    let mut config = Config::default();
    config
        .style_specs
        .extend(crate::prelude::prelude_style_specs());
    config.parsers.extend(crate::prelude::prelude_parsers());

    for (form, provenance) in forms {
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
                let mut rule = rule.value;
                rule.provenance = provenance.clone();
                config.rules.push(rule);
            }
            "define" => {
                let mut define = crate::rule::parse_define(form)?;
                define.provenance = provenance.clone();
                config.defines.push(define);
            }
            "safe-env-vars" => {
                parse_safe_env_vars(&list[1..], &mut config.security, form.span())?;
                if provenance.is_loaded() {
                    config.security.has_loaded_env_vars = true;
                }
            }
            "check" => {
                let checks = parse_check(&list[1..], form.span())?;
                config.checks.extend(checks);
            }
            "audit" => {
                if !matches!(provenance, Provenance::PrimaryConfig) {
                    return Err(RawError::new(
                        "(audit …) is permitted only in the primary config",
                        form.span(),
                    )
                    .with_help(
                        "a loaded or repo-local file must not configure the Audit log; \
                         set (audit …) in your primary config, or use the --audit-* flags \
                         / MAYI_AUDIT_* environment variables",
                    ));
                }
                config.audit = parse_audit_form(list, form.span())?;
            }
            "define-arg-style" => {
                let mut spec = crate::style::parse_style_definition(form)?;
                spec.provenance = provenance.clone();
                push_style_spec(&mut config, spec);
            }
            "parser" => {
                let mut parser = crate::parser_form::parse_parser_form(form)?;
                parser.provenance = provenance.clone();
                push_parser(&mut config, parser);
            }
            "load" => {
                return Err(RawError::new(
                    "load forms should be resolved before parsing",
                    list[0].span(),
                )
                .with_help(
                    "this is an internal error — load expansion should happen in the IO layer",
                ));
            }
            other => {
                return Err(RawError::new(
                    format!("unknown top-level form: {other}"),
                    list[0].span(),
                )
                .with_help(
                    "valid top-level forms: rule, define, safe-env-vars, check, audit, define-arg-style, parser",
                ));
            }
        }
    }

    Ok(config)
}

/// Parse an `(audit (threshold :KW) (file "PATH"))` form into an
/// [`AuditConfig`]. The body is alist-style head-keyed sub-forms (like
/// `(define-arg-style …)`), not a keyword plist; the threshold is a
/// closed-set keyword value (like `(pun :allow)`). Both sub-forms are
/// optional; an omitted threshold defaults to `:off`.
fn parse_audit_form(list: &[Sexpr], _span: Span) -> Result<AuditConfig, RawError> {
    let mut audit = AuditConfig::default();
    let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

    for sub in &list[1..] {
        let sub_list = sub
            .as_list()
            .ok_or_else(|| RawError::new("audit body items must be lists", sub.span()))?;
        if sub_list.is_empty() {
            return Err(RawError::new("empty audit sub-form", sub.span()));
        }
        let tag = sub_list[0].as_atom().ok_or_else(|| {
            RawError::new("audit sub-form tag must be an atom", sub_list[0].span())
        })?;

        let attr_name: &'static str = match tag {
            "threshold" => "threshold",
            "file" => "file",
            other => {
                return Err(RawError::new(
                    format!("unknown audit sub-form: {other}"),
                    sub.span(),
                )
                .with_help("valid audit sub-forms: (threshold :off|:deny|:ask|:all) (file \"PATH\")"));
            }
        };

        if !seen.insert(attr_name) {
            eprintln!(
                "warning: duplicate (audit …) sub-form `{attr_name}` — last declaration wins"
            );
        }

        match attr_name {
            "threshold" => {
                if sub_list.len() != 2 {
                    return Err(RawError::new(
                        "(threshold …) takes exactly one keyword",
                        sub.span(),
                    ));
                }
                let kw = sub_list[1].as_atom().ok_or_else(|| {
                    RawError::new("(threshold …) value must be a keyword", sub_list[1].span())
                })?;
                audit.threshold = AuditThreshold::from_keyword(kw).ok_or_else(|| {
                    RawError::new(
                        format!(
                            "invalid audit threshold {kw}: valid values are :off, :deny, :ask, :all"
                        ),
                        sub_list[1].span(),
                    )
                    .with_help("valid thresholds: :off, :deny, :ask, :all")
                })?;
            }
            "file" => {
                if sub_list.len() != 2 {
                    return Err(RawError::new(
                        "(file …) takes exactly one string",
                        sub.span(),
                    ));
                }
                let path = sub_list[1].as_atom_or_str().ok_or_else(|| {
                    RawError::new("(file …) value must be a string", sub_list[1].span())
                })?;
                audit.file = Some(std::path::PathBuf::from(path));
            }
            _ => unreachable!(),
        }
    }

    Ok(audit)
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

/// Parse check form: (check (DECISION "cmd" REASON?) …)
/// Supports nested with-facts: (check (with-facts [[:key]] (allow "cmd")))
pub(crate) fn parse_check(args: &[Sexpr], check_span: Span) -> Result<Vec<Check>, RawError> {
    parse_check_items(args, &ContextFacts::default(), check_span)
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
        .with_help("use (with-facts [[:client/opencode]] (allow \"cmd\"))"));
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

/// Parse check items with a given context. Each item must be either a
/// `(with-facts …)` wrapper or a `(DECISION "cmd" REASON?)` form.
fn parse_check_items(
    items: &[Sexpr],
    context: &ContextFacts,
    check_span: Span,
) -> Result<Vec<Check>, RawError> {
    let mut checks = Vec::new();

    for item in items {
        let list = item.as_list().ok_or_else(|| {
            RawError::new(
                "check items must be lists like (allow \"cmd\") or (with-facts …)",
                item.span(),
            )
        })?;
        if list.is_empty() {
            return Err(RawError::new("empty check item", item.span()));
        }
        let head = list[0]
            .as_atom()
            .ok_or_else(|| RawError::new("check item tag must be an atom", list[0].span()))?;

        if head == "with-facts" {
            let nested = parse_with_facts(list, context, check_span)?;
            checks.extend(nested);
            continue;
        }

        let expected = parse_decision_tag(head, list[0].span())?;
        if list.len() < 2 {
            return Err(RawError::new(
                format!("({head} …) requires a command string"),
                item.span(),
            ));
        }
        if list.len() > 3 {
            return Err(RawError::new(
                format!("({head} \"cmd\" REASON?) takes at most one optional reason"),
                item.span(),
            ));
        }
        let cmd = list[1]
            .as_atom_or_str()
            .ok_or_else(|| RawError::new("check command must be a string", list[1].span()))?;
        // REASON is currently accepted but discarded — the existing Check struct
        // does not carry it. Decision verbs landing in §4 will surface reasons
        // through traces; check reasons can ride on that.

        checks.push(Check {
            command: cmd.to_string(),
            expected,
            context: context.clone(),
            span: list[1].span(),
        });
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
        let config = parse_config(r#"(check (allow "git status") (deny "rm -rf /"))"#).unwrap();
        assert_eq!(config.checks.len(), 2);
        assert_eq!(config.checks[0].command, "git status");
        assert!(matches!(config.checks[0].expected, Decision::Allow));
        assert_eq!(config.checks[1].command, "rm -rf /");
        assert!(matches!(config.checks[1].expected, Decision::Deny));
    }

    #[test]
    fn parse_check_with_ask() {
        let config = parse_config(r#"(check (ask "ssh prod-server"))"#).unwrap();
        assert_eq!(config.checks.len(), 1);
        assert!(matches!(config.checks[0].expected, Decision::Ask));
    }

    #[test]
    fn parse_check_with_with_facts() {
        let config = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode] [:via/ssh]]
                    (allow "git push")))
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
                        (allow "git push"))))
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
                    (allow "npm install")))
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
        let err = parse_config(r#"(check (invalid "cmd"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown decision tag"));
    }

    #[test]
    fn check_accepts_string_commands() {
        let config = parse_config(r#"(check (allow "git status") (deny "rm"))"#).unwrap();
        assert_eq!(config.checks.len(), 2);
        assert_eq!(config.checks[0].command, "git status");
        assert_eq!(config.checks[1].command, "rm");
    }

    #[test]
    fn check_requires_command_after_decision() {
        let err = parse_config(r#"(check (allow))"#).expect_err("expected error");
        assert!(format!("{err}").contains("requires a command"));
    }

    #[test]
    fn duplicate_fact_key_is_error() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode] [:client/opencode]]
                    (allow "cmd")))
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
                    (allow "cmd")))
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
            
            (rule "git" (and (or (positional "status") (positional "log")) (allow)))
            (rule "git" (and (positional "push") (ask)))

            (check
                (allow "git status")
                (with-facts [[:client/opencode]] (allow "git push"))
                (deny "rm -rf /"))
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
                    (invalid "cmd")))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("unknown decision tag"));
    }

    #[test]
    fn check_missing_command_in_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    (allow)))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("requires a command"));
    }

    #[test]
    fn check_non_atom_command_in_items() {
        let err = parse_config(
            r#"
            (check
                (with-facts [[:client/opencode]]
                    (allow (not-a-string))))
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
                    (allow "cmd")))
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
                    (allow "cmd")))
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
                    (allow "cmd")))
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
                    (allow "cmd")))
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
                    ((not-an-atom) "cmd")))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("tag must be an atom"));
    }

    #[test]
    fn parse_check_non_atom_decision() {
        let err = parse_config(r#"(check ((not-an-atom) "cmd"))"#).expect_err("expected error");
        assert!(format!("{err}").contains("tag must be an atom"));
    }

    #[test]
    fn parse_check_with_non_list_with_facts() {
        let err = parse_config(r#"(check (with-facts :not-a-list))"#).expect_err("expected error");
        assert!(format!("{err}").contains("with-facts requires a fact vector"));
    }

    #[test]
    fn load_form_reaching_parser_is_error() {
        let err = parse_config(r#"(load "rules/*.lisp")"#).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("load forms should be resolved before parsing"),
            "got: {msg}"
        );
    }

    // --- audit form ---

    #[test]
    fn parse_audit_form_sets_threshold_and_file() {
        let config = parse_config(r#"(audit (threshold :ask) (file "x.jsonl"))"#).unwrap();
        assert_eq!(config.audit.threshold, AuditThreshold::Ask);
        assert_eq!(
            config.audit.file.as_deref(),
            Some(std::path::Path::new("x.jsonl"))
        );
    }

    #[test]
    fn audit_defaults_to_off_when_absent() {
        let config = parse_config(r#"(rule "echo" (allow))"#).unwrap();
        assert_eq!(config.audit.threshold, AuditThreshold::Off);
        assert!(config.audit.file.is_none());
    }

    #[test]
    fn audit_invalid_threshold_is_load_error() {
        let err = parse_config(r#"(audit (threshold :loud))"#).expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains(":off"), "got: {msg}");
        assert!(msg.contains(":deny"), "got: {msg}");
        assert!(msg.contains(":ask"), "got: {msg}");
        assert!(msg.contains(":all"), "got: {msg}");
    }

    #[test]
    fn audit_unknown_subform_is_error() {
        let err = parse_config(r#"(audit (wibble :ask))"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown audit sub-form"));
    }

    #[test]
    fn audit_form_with_loaded_provenance_is_rejected() {
        let forms = vec![(
            first_form(r#"(audit (threshold :off))"#),
            Provenance::Loaded {
                path: std::path::PathBuf::from("/tmp/loaded.lisp"),
            },
        )];
        let err = parse_config_from_tagged_sexprs(&forms).expect_err("expected error");
        assert!(
            format!("{err}").contains("only in the primary config"),
            "got: {err}"
        );
    }

    #[test]
    fn audit_form_from_primary_provenance_is_accepted() {
        let forms = vec![(
            first_form(r#"(audit (threshold :deny))"#),
            Provenance::PrimaryConfig,
        )];
        let config = parse_config_from_tagged_sexprs(&forms).unwrap();
        assert_eq!(config.audit.threshold, AuditThreshold::Deny);
    }

    fn first_form(input: &str) -> Sexpr {
        let (forms, errs) = may_i_sexpr::parse(input);
        assert!(errs.is_empty(), "{errs:?}");
        forms.into_iter().next().unwrap()
    }

    use may_i_core::ast::AuditThreshold;
    use may_i_sexpr::test_generators::any_canonical_config_cst;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            max_shrink_iters: 50,
            .. ProptestConfig::default()
        })]

        #[test]
        fn config_parse_roundtrip(forms in any_canonical_config_cst()) {
            // Step 1: CST → text → parse
            let text1: String = forms.iter().map(|f| f.serialize()).collect::<Vec<_>>().join("\n");
            let config1 = parse_config(&text1);
            prop_assert!(config1.is_ok(), "first parse failed: {:?}\ntext: {}", config1.err(), text1);
            let config1 = config1.unwrap();

            let rule_count = forms.iter().filter(|f| {
                f.as_list().is_some_and(|list| {
                    list.first().is_some_and(|first| first.as_atom() == Some("rule"))
                })
            }).count();
            prop_assert_eq!(config1.rules.len(), rule_count,
                "rule count mismatch: expected {} from CST, got {}\ntext: {}",
                rule_count, config1.rules.len(), text1);

            // Step 2: serialize (CST roundtrip) → re-parse → compare
            let (reparsed_cst, errors) = may_i_sexpr::parse_cst(&text1);
            prop_assert!(errors.is_empty(), "CST re-parse failed: {:?}", errors);
            let text2: String = reparsed_cst.iter().map(|f| f.serialize()).collect::<Vec<_>>().join("\n");

            let config2 = parse_config(&text2);
            prop_assert!(config2.is_ok(), "re-parse failed: {:?}\ntext: {}", config2.err(), text2);
            let config2 = config2.unwrap();

            // Rule count must survive the roundtrip
            prop_assert_eq!(config1.rules.len(), config2.rules.len(),
                "rule count differs after serialize roundtrip:\n  text1: {}\n  text2: {}", text1, text2);
        }
    }
}

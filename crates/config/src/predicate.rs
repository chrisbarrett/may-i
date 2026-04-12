// Unified predicate parser for the unified DSL.
// Task 2.2: Implement fact query parser for `(has ...)` forms
// Task 2.4: Implement boolean combinator parsers (`and`, `or`, `not`)
// Task 2.5: Implement unified predicate parser that dispatches to fact or arg parsers

use may_i_core::Keyword;
use may_i_core::ast::Predicate;
use may_i_core::predicates::FactQuery;
use may_i_sexpr::{RawError, Sexpr};

/// Parse a unified predicate from an s-expression.
///
/// This is the main entry point for predicate parsing. It handles:
/// - Fact queries: `(fact? FACT-QUERY)` (renamed from `has`)
/// - Argument patterns: `(positional ...)`, `(exact ...)`, etc.
/// - Boolean combinators: `(and PREDICATE ...)`, `(or PREDICATE ...)`, `(not PREDICATE)`
/// - Named predicate references (will be resolved later)
#[must_use = "parsed predicate should be used"]
pub fn parse_predicate(sexpr: &Sexpr) -> Result<Predicate, RawError> {
    // If it's an atom, it's a named predicate reference
    if let Some(name) = sexpr.as_atom() {
        // Named predicate reference - will be resolved during validation
        return Ok(Predicate::Named(name.to_string()));
    }

    let list = sexpr
        .as_list()
        .ok_or_else(|| RawError::new("predicate must be a list or atom reference", sexpr.span()))?;

    if list.is_empty() {
        return Err(RawError::new("empty predicate", sexpr.span()));
    }

    let tag = list[0]
        .as_atom()
        .ok_or_else(|| RawError::new("predicate tag must be an atom", list[0].span()))?;

    match tag {
        // Fact query (renamed from `has` to `fact?`)
        "fact?" => {
            if list.len() != 2 {
                return Err(RawError::new(
                    "fact? must have exactly one fact query",
                    sexpr.span(),
                ));
            }
            let query = parse_fact_query(&list[1])?;
            Ok(Predicate::Fact(query))
        }

        // Boolean combinators
        "and" => {
            if list.len() < 2 {
                return Err(RawError::new(
                    "and must have at least one predicate",
                    sexpr.span(),
                ));
            }
            let predicates: Result<Vec<Predicate>, _> =
                list[1..].iter().map(parse_predicate).collect();
            Ok(Predicate::And(predicates?))
        }
        "or" => {
            if list.len() < 2 {
                return Err(RawError::new(
                    "or must have at least one predicate",
                    sexpr.span(),
                ));
            }
            let predicates: Result<Vec<Predicate>, _> =
                list[1..].iter().map(parse_predicate).collect();
            Ok(Predicate::Or(predicates?))
        }
        "not" => {
            if list.len() != 2 {
                return Err(RawError::new(
                    "not must have exactly one predicate",
                    sexpr.span(),
                ));
            }
            let inner = parse_predicate(&list[1])?;
            Ok(Predicate::Not(Box::new(inner)))
        }

        // Argument patterns - delegate to the argument pattern parser
        "positional" | "exact" | "anywhere" | "forbidden" | "=" => {
            let arg_pattern = crate::pattern::parse_arg_pattern(sexpr)?;
            Ok(Predicate::Arg(arg_pattern))
        }

        other => Err(
            RawError::new(format!("unknown predicate form: {other}"), list[0].span()).with_help(
                "valid predicates: fact?, and, or, not, positional, exact, anywhere, forbidden, =",
            ),
        ),
    }
}

/// Parse a fact query from an s-expression.
///
/// Syntax:
/// - `:key` or `[:key]` - presence check
/// - `[:key PATTERN]` - value check with pattern
fn parse_fact_query(sexpr: &Sexpr) -> Result<FactQuery, RawError> {
    // Bare atom: presence check without vector syntax
    if sexpr.as_atom().is_some() {
        let key = parse_context_key(sexpr)?;
        return Ok(FactQuery::Presence { key });
    }

    // Vector syntax: presence or value check
    let items = match sexpr {
        Sexpr::Vector(items, _) => items,
        _ => {
            return Err(RawError::new(
                "fact query must be a namespaced key or vector like [:key] or [:key pattern]",
                sexpr.span(),
            ));
        }
    };

    match items.len() {
        1 => {
            let key = parse_context_key(&items[0])?;
            Ok(FactQuery::Presence { key })
        }
        2 => {
            let key = parse_context_key(&items[0])?;
            let pattern = parse_fact_pattern(&items[1])?;
            Ok(FactQuery::Value { key, pattern })
        }
        _ => Err(RawError::new(
            "fact query vectors must contain a key or a key and value pattern",
            sexpr.span(),
        )),
    }
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

/// Parse a fact pattern for value matching.
use may_i_core::predicates::FactPattern;

fn parse_fact_pattern(sexpr: &Sexpr) -> Result<FactPattern, RawError> {
    match sexpr {
        Sexpr::Symbol(s, _) if s == "*" => Ok(FactPattern::Wildcard),
        Sexpr::String(s, _) | Sexpr::Symbol(s, _) | Sexpr::Keyword(s, _) => {
            Ok(FactPattern::Literal(s.clone()))
        }
        Sexpr::List(list, span) => {
            if list.is_empty() {
                return Err(RawError::new("empty fact pattern", *span));
            }

            let tag = list[0]
                .as_atom()
                .ok_or_else(|| RawError::new("fact pattern tag must be an atom", list[0].span()))?;

            match tag {
                "regex" => {
                    if list.len() != 2 {
                        return Err(RawError::new("regex must have exactly one pattern", *span));
                    }
                    let pat = list[1].as_atom_or_str().ok_or_else(|| {
                        RawError::new("regex pattern must be a string", list[1].span())
                    })?;
                    let re = regex::Regex::new(pat).map_err(|err| {
                        RawError::new(format!("invalid regex '{pat}': {err}"), list[1].span())
                    })?;
                    Ok(FactPattern::Regex(re))
                }
                "and" => {
                    if list.len() < 2 {
                        return Err(RawError::new("and must have at least one pattern", *span));
                    }
                    let patterns: Result<Vec<_>, _> =
                        list[1..].iter().map(parse_fact_pattern).collect();
                    Ok(FactPattern::And(patterns?))
                }
                "or" => {
                    if list.len() < 2 {
                        return Err(RawError::new("or must have at least one pattern", *span));
                    }
                    let patterns: Result<Vec<_>, _> =
                        list[1..].iter().map(parse_fact_pattern).collect();
                    Ok(FactPattern::Or(patterns?))
                }
                "not" => {
                    if list.len() != 2 {
                        return Err(RawError::new("not must have exactly one pattern", *span));
                    }
                    let inner = parse_fact_pattern(&list[1])?;
                    Ok(FactPattern::Not(Box::new(inner)))
                }
                other => Err(RawError::new(
                    format!("unknown fact pattern: {other}"),
                    list[0].span(),
                )
                .with_help("valid fact patterns: string, *, regex, and, or, not")),
            }
        }
        Sexpr::Vector(_, span) => Err(RawError::new(
            "fact patterns do not support nested vector syntax",
            *span,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::pattern::{ArgPattern, MatchMode};
    use may_i_core::predicates::FactPattern;
    use may_i_sexpr::RawError;

    fn parse_pred(input: &str) -> Result<Predicate, RawError> {
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
        parse_predicate(&forms[0])
    }

    #[test]
    fn parse_fact_presence_bare() {
        let pred = parse_pred(r#"(fact? :via/ssh)"#).unwrap();
        match pred {
            Predicate::Fact(FactQuery::Presence { key }) => {
                assert_eq!(key, ":via/ssh");
            }
            _ => panic!("expected Fact with Presence"),
        }
    }

    #[test]
    fn parse_fact_presence_vector() {
        let pred = parse_pred(r#"(fact? [:via/ssh])"#).unwrap();
        match pred {
            Predicate::Fact(FactQuery::Presence { key }) => {
                assert_eq!(key, ":via/ssh");
            }
            _ => panic!("expected Fact with Presence"),
        }
    }

    #[test]
    fn parse_fact_value() {
        let pred = parse_pred(r#"(fact? [:opencode/agent "build"])"#).unwrap();
        match pred {
            Predicate::Fact(FactQuery::Value { key, pattern }) => {
                assert_eq!(key, ":opencode/agent");
                assert!(matches!(pattern, FactPattern::Literal(s) if s == "build"));
            }
            _ => panic!("expected Fact with Value"),
        }
    }

    #[test]
    fn parse_and_predicate() {
        let pred = parse_pred(r#"(and (fact? :via/ssh) (positional "push"))"#).unwrap();
        match pred {
            Predicate::And(preds) => {
                assert_eq!(preds.len(), 2);
                assert!(matches!(preds[0], Predicate::Fact(_)));
                assert!(matches!(preds[1], Predicate::Arg(_)));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn parse_or_predicate() {
        let pred =
            parse_pred(r#"(or (fact? :client/claude-code) (fact? :client/opencode))"#).unwrap();
        match pred {
            Predicate::Or(preds) => {
                assert_eq!(preds.len(), 2);
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn parse_not_predicate() {
        let pred = parse_pred(r#"(not (fact? :dangerous))"#).unwrap();
        match pred {
            Predicate::Not(inner) => {
                assert!(matches!(inner.as_ref(), Predicate::Fact(_)));
            }
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn nested_boolean_combinators() {
        let pred = parse_pred(
            r#"
            (and
                (fact? :via/ssh)
                (or (positional "push")
                    (positional "pull")))
        "#,
        )
        .unwrap();

        match pred {
            Predicate::And(preds) => {
                assert_eq!(preds.len(), 2);
                assert!(matches!(preds[1], Predicate::Or(_)));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn non_namespaced_key_is_error() {
        let err = parse_pred(r#"(fact? invalid-key)"#).expect_err("expected error");
        assert!(format!("{err}").contains("namespaced"));
    }

    #[test]
    fn parse_named_predicate_reference() {
        let pred = parse_pred(r#"safe-git"#).unwrap();
        match pred {
            Predicate::Named(name) => {
                assert_eq!(name, "safe-git");
            }
            _ => panic!("expected Named, got {:?}", pred),
        }
    }

    #[test]
    fn parse_fact_with_regex() {
        let pred = parse_pred(r#"(fact? [:ssh/host (regex "^prod-")])"#).unwrap();
        match pred {
            Predicate::Fact(FactQuery::Value { key, pattern }) => {
                assert_eq!(key, ":ssh/host");
                assert!(matches!(pattern, FactPattern::Regex(_)));
            }
            _ => panic!("expected Fact with Regex Value"),
        }
    }

    #[test]
    fn parse_fact_with_wildcard() {
        let pred = parse_pred(r#"(fact? [:ssh/host *])"#).unwrap();
        match pred {
            Predicate::Fact(FactQuery::Value { key, pattern }) => {
                assert_eq!(key, ":ssh/host");
                assert!(matches!(pattern, FactPattern::Wildcard));
            }
            _ => panic!("expected Fact with Wildcard Value"),
        }
    }

    #[test]
    fn parse_and_preserves_single_predicate() {
        // Parser preserves (and X) as And([X]), doesn't flatten
        let pred = parse_pred(r#"(and (fact? :via/ssh))"#).unwrap();
        match pred {
            Predicate::And(preds) => {
                assert_eq!(preds.len(), 1);
            }
            _ => panic!("expected And with single element"),
        }
    }

    #[test]
    fn parse_or_preserves_single_predicate() {
        // Parser preserves (or X) as Or([X]), doesn't flatten
        let pred = parse_pred(r#"(or (fact? :via/ssh))"#).unwrap();
        match pred {
            Predicate::Or(preds) => {
                assert_eq!(preds.len(), 1);
            }
            _ => panic!("expected Or with single element"),
        }
    }

    #[test]
    fn parse_deeply_nested_combinators() {
        let pred = parse_pred(
            r#"
            (or
                (and
                    (fact? :via/ssh)
                    (not (positional "--force")))
                (and
                    (fact? :local)
                    (positional "--safe")))
        "#,
        )
        .unwrap();

        match pred {
            Predicate::Or(preds) => {
                assert_eq!(preds.len(), 2);
                assert!(matches!(preds[0], Predicate::And(_)));
                assert!(matches!(preds[1], Predicate::And(_)));
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn parse_arg_predicate_positional() {
        let pred = parse_pred(r#"(positional "push")"#).unwrap();
        match pred {
            Predicate::Arg(ArgPattern::Ordered {
                mode: MatchMode::Positional,
                ..
            }) => {}
            _ => panic!("expected Arg with Positional"),
        }
    }

    #[test]
    fn parse_arg_predicate_exact() {
        let pred = parse_pred(r#"(exact "status")"#).unwrap();
        match pred {
            Predicate::Arg(ArgPattern::Ordered {
                mode: MatchMode::Exact,
                ..
            }) => {}
            _ => panic!("expected Arg with Exact"),
        }
    }

    #[test]
    fn parse_arg_predicate_anywhere() {
        let pred = parse_pred(r#"(anywhere "--force")"#).unwrap();
        match pred {
            Predicate::Arg(ArgPattern::Anywhere(_)) => {}
            _ => panic!("expected Arg with Anywhere"),
        }
    }

    #[test]
    fn parse_arg_predicate_forbidden() {
        let pred = parse_pred(r#"(forbidden "--dangerous")"#).unwrap();
        match pred {
            Predicate::Arg(ArgPattern::Forbidden(_)) => {}
            _ => panic!("expected Arg with Forbidden"),
        }
    }

    #[test]
    fn parse_empty_predicate_error() {
        let err = parse_pred(r#"()"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty predicate"));
    }

    #[test]
    fn parse_fact_without_args_error() {
        let err = parse_pred(r#"(fact?)"#).expect_err("expected error");
        assert!(format!("{err}").contains("fact? must have"));
    }

    #[test]
    fn parse_fact_with_too_many_args_error() {
        let err = parse_pred(r#"(fact? :a :b :c)"#).expect_err("expected error");
        assert!(format!("{err}").contains("fact? must have"));
    }

    #[test]
    fn parse_not_without_arg_error() {
        let err = parse_pred(r#"(not)"#).expect_err("expected error");
        assert!(format!("{err}").contains("not must have exactly one predicate"));
    }

    #[test]
    fn parse_non_namespaced_key_in_fact_error() {
        let err = parse_pred(r#"(fact? "plain-key")"#).expect_err("expected error");
        assert!(format!("{err}").contains("namespaced"));
    }

    #[test]
    fn parse_unknown_predicate_error() {
        let err = parse_pred(r#"(unknown "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown predicate"));
    }

    #[test]
    fn parse_and_without_args_error() {
        let err = parse_pred(r#"(and)"#).expect_err("expected error");
        assert!(format!("{err}").contains("and must have"));
    }

    #[test]
    fn parse_or_without_args_error() {
        let err = parse_pred(r#"(or)"#).expect_err("expected error");
        assert!(format!("{err}").contains("or must have"));
    }

    #[test]
    fn parse_not_with_too_many_args_error() {
        let err = parse_pred(r#"(not (fact? :a) (fact? :b))"#).expect_err("expected error");
        assert!(format!("{err}").contains("not must have exactly one predicate"));
    }

    #[test]
    fn parse_fact_query_with_three_items_error() {
        let err = parse_pred(r#"(fact? [:key a b c])"#).expect_err("expected error");
        assert!(format!("{err}").contains("fact query vectors must contain"));
    }

    #[test]
    fn parse_invalid_regex_in_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key (regex "[invalid")])"#).expect_err("expected error");
        assert!(format!("{err}").contains("invalid regex"));
    }

    #[test]
    fn parse_empty_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key ()])"#).expect_err("expected error");
        assert!(format!("{err}").contains("empty fact pattern"));
    }

    #[test]
    fn parse_unknown_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key (unknown "test")])"#).expect_err("expected error");
        assert!(format!("{err}").contains("unknown fact pattern"));
    }

    #[test]
    fn parse_and_in_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key (and)])"#).expect_err("expected error");
        assert!(format!("{err}").contains("and must have at least one pattern"));
    }

    #[test]
    fn parse_or_in_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key (or)])"#).expect_err("expected error");
        assert!(format!("{err}").contains("or must have at least one pattern"));
    }

    #[test]
    fn parse_not_in_fact_pattern_error() {
        let err = parse_pred(r#"(fact? [:key (not)])"#).expect_err("expected error");
        assert!(format!("{err}").contains("not must have exactly one pattern"));
    }

    #[test]
    fn parse_not_in_fact_pattern_with_too_many_args_error() {
        let err = parse_pred(r#"(fact? [:key (not a b)])"#).expect_err("expected error");
        assert!(format!("{err}").contains("not must have exactly one pattern"));
    }

    #[test]
    fn parse_nested_vector_syntax_error() {
        let err = parse_pred(r#"(fact? [:key [:nested]])"#).expect_err("expected error");
        assert!(format!("{err}").contains("nested vector syntax"));
    }

    #[test]
    fn parse_non_atom_tag_in_fact_pattern_error() {
        // Use a list as the tag (not an atom) - the inner (1 2) is a list, not an atom
        let err = parse_pred(r#"(fact? [:key ((1 2) "arg")])"#).expect_err("expected error");
        assert!(format!("{err}").contains("fact pattern tag must be an atom"));
    }

    #[test]
    fn parse_non_atom_predicate_tag_error() {
        let err = parse_pred(r#"(("not an atom") "test")"#).expect_err("expected error");
        assert!(format!("{err}").contains("predicate tag must be an atom"));
    }
}

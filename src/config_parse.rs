// Configuration parsing — R10, R10a–R10f
// S-expression configuration for authorization rules, wrappers, and security.

use crate::sexpr::Sexpr;
use crate::types::{
    ArgMatcher, CommandMatcher, CondBranch, Config, Decision, Example, Pattern, Rule,
    SecurityConfig, Wrapper, WrapperKind,
};

/// Parse an s-expression config string into Config.
pub fn parse(input: &str) -> Result<Config, String> {
    let forms = crate::sexpr::parse(input)?;
    let mut rules = Vec::new();
    let mut wrappers = Vec::new();
    let mut security = SecurityConfig::default();

    for form in &forms {
        let list = form.as_list().ok_or("top-level form must be a list")?;
        if list.is_empty() {
            return Err("empty top-level form".into());
        }
        let tag = list[0].as_atom().ok_or("form tag must be an atom")?;
        match tag {
            "rule" => rules.push(parse_rule(&list[1..])?),
            "wrapper" => wrappers.push(parse_wrapper(&list[1..])?),
            "blocked-paths" => {
                for item in &list[1..] {
                    let s = item.as_atom().ok_or("blocked-paths entry must be a string")?;
                    let re = regex::Regex::new(s)
                        .map_err(|e| format!("invalid blocked-path regex '{s}': {e}"))?;
                    if !security
                        .blocked_paths
                        .iter()
                        .any(|existing| existing.as_str() == re.as_str())
                    {
                        security.blocked_paths.push(re);
                    }
                }
            }
            "safe-env-vars" => {
                for item in &list[1..] {
                    let s = item.as_atom().ok_or("safe-env-vars entry must be a string")?;
                    security.safe_env_vars.insert(s.to_string());
                }
            }
            other => return Err(format!("unknown top-level form: {other}")),
        }
    }

    Ok(Config {
        rules,
        wrappers,
        security,
    })
}

fn parse_effect(list: &[Sexpr]) -> Result<(Decision, Option<String>), String> {
    if list.len() < 2 {
        return Err("effect must have a keyword (:allow, :deny, or :ask)".into());
    }
    let kw = list[1].as_atom().ok_or("effect keyword must be an atom")?;
    let decision = match kw {
        ":allow" => Decision::Allow,
        ":deny" => Decision::Deny,
        ":ask" => Decision::Ask,
        other => return Err(format!("unknown effect keyword: {other}")),
    };
    let reason = if list.len() > 2 {
        Some(
            list[2]
                .as_atom()
                .ok_or("reason must be a string")?
                .to_string(),
        )
    } else {
        None
    };
    Ok((decision, reason))
}

fn parse_cond_branches(list: &[Sexpr]) -> Result<Vec<CondBranch>, String> {
    let branches = &list[1..];
    if branches.is_empty() {
        return Err("cond must have at least one branch".into());
    }
    let mut result = Vec::new();
    for branch in branches {
        let items = branch.as_list().ok_or("cond branch must be a list")?;
        if items.is_empty() {
            return Err("empty cond branch".into());
        }
        // First element: matcher or wildcard
        let matcher = match &items[0] {
            Sexpr::Atom(s) if s == "_" || s == "t" => None,
            other => Some(parse_matcher(other)?),
        };
        // Remaining elements: find (effect ...)
        let mut decision = None;
        let mut reason = None;
        for item in &items[1..] {
            let il = item.as_list().ok_or("cond branch element must be a list")?;
            if il.is_empty() {
                return Err("empty cond branch element".into());
            }
            let tag = il[0].as_atom().ok_or("cond branch element tag must be an atom")?;
            if tag == "effect" {
                let (d, r) = parse_effect(il)?;
                decision = Some(d);
                reason = r;
            } else {
                return Err(format!("unknown cond branch element: {tag}"));
            }
        }
        result.push(CondBranch {
            matcher,
            decision: decision.ok_or("cond branch must have an effect")?,
            reason,
        });
    }
    Ok(result)
}

fn parse_rule(parts: &[Sexpr]) -> Result<Rule, String> {
    let mut command = None;
    let mut matcher = None;
    let mut decision = None;
    let mut reason = None;
    let mut examples = Vec::new();

    for part in parts {
        let list = part.as_list().ok_or("rule element must be a list")?;
        if list.is_empty() {
            return Err("empty rule element".into());
        }
        let tag = list[0].as_atom().ok_or("rule element tag must be an atom")?;
        match tag {
            "command" => {
                if list.len() != 2 {
                    return Err("command must have exactly one value".into());
                }
                command = Some(parse_command(&list[1])?);
            }
            "args" => {
                if list.len() != 2 {
                    return Err("args must have exactly one matcher".into());
                }
                matcher = Some(parse_matcher(&list[1])?);
            }
            "effect" => {
                let (d, r) = parse_effect(list)?;
                decision = Some(d);
                reason = r;
            }
            "example" => {
                if list.len() < 3 {
                    return Err("example must have decision keyword and command".into());
                }
                let expected = match list[1].as_atom().ok_or("example decision must be an atom")? {
                    ":allow" => Decision::Allow,
                    ":deny" => Decision::Deny,
                    ":ask" => Decision::Ask,
                    other => return Err(format!("unknown expected decision: {other}")),
                };
                let cmd = list[2]
                    .as_atom()
                    .ok_or("example command must be a string")?;
                examples.push(Example {
                    command: cmd.to_string(),
                    expected,
                });
            }
            other => return Err(format!("unknown rule element: {other}")),
        }
    }

    // Validate: top-level cond matcher is mutually exclusive with effect
    let is_top_cond = matches!(&matcher, Some(ArgMatcher::Cond(_)));
    if is_top_cond && decision.is_some() {
        return Err("cond and effect are mutually exclusive in a rule".into());
    }
    if !is_top_cond && decision.is_none() {
        return Err("rule must have an effect (or a top-level cond matcher)".into());
    }

    Ok(Rule {
        command: command.ok_or("rule must have a command")?,
        matcher,
        decision,
        reason,
        examples,
    })
}

fn parse_command(sexpr: &Sexpr) -> Result<CommandMatcher, String> {
    match sexpr {
        Sexpr::Atom(s) => Ok(CommandMatcher::Exact(s.clone())),
        Sexpr::List(list) => {
            if list.is_empty() {
                return Err("empty command form".into());
            }
            let tag = list[0].as_atom().ok_or("command form tag must be an atom")?;
            match tag {
                "or" => {
                    let names: Result<Vec<String>, _> = list[1..]
                        .iter()
                        .map(|s| {
                            s.as_atom()
                                .map(|s| s.to_string())
                                .ok_or("or values must be strings".to_string())
                        })
                        .collect();
                    Ok(CommandMatcher::List(names?))
                }
                "regex" => {
                    if list.len() != 2 {
                        return Err("regex must have exactly one pattern".into());
                    }
                    let pat = list[1]
                        .as_atom()
                        .ok_or("regex pattern must be a string")?;
                    let re = regex::Regex::new(pat)
                        .map_err(|e| format!("invalid command regex: {e}"))?;
                    Ok(CommandMatcher::Regex(re))
                }
                other => Err(format!("unknown command form: {other}")),
            }
        }
    }
}

fn parse_matcher(sexpr: &Sexpr) -> Result<ArgMatcher, String> {
    let list = sexpr.as_list().ok_or("matcher must be a list")?;
    if list.is_empty() {
        return Err("empty matcher".into());
    }
    let tag = list[0].as_atom().ok_or("matcher tag must be an atom")?;
    match tag {
        "positional" => {
            let patterns: Result<Vec<Pattern>, _> =
                list[1..].iter().map(parse_pattern).collect();
            Ok(ArgMatcher::Positional(patterns?))
        }
        "exact" => {
            let patterns: Result<Vec<Pattern>, _> =
                list[1..].iter().map(parse_pattern).collect();
            Ok(ArgMatcher::ExactPositional(patterns?))
        }
        "anywhere" => {
            let patterns: Result<Vec<Pattern>, _> =
                list[1..].iter().map(parse_pattern).collect();
            Ok(ArgMatcher::Anywhere(patterns?))
        }
        "forbidden" => {
            let patterns: Result<Vec<Pattern>, _> =
                list[1..].iter().map(parse_pattern).collect();
            Ok(ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(patterns?))))
        }
        "and" => {
            let matchers: Result<Vec<ArgMatcher>, _> =
                list[1..].iter().map(parse_matcher).collect();
            Ok(ArgMatcher::And(matchers?))
        }
        "or" => {
            let matchers: Result<Vec<ArgMatcher>, _> =
                list[1..].iter().map(parse_matcher).collect();
            Ok(ArgMatcher::Or(matchers?))
        }
        "not" => {
            if list.len() != 2 {
                return Err("not must have exactly one matcher".into());
            }
            Ok(ArgMatcher::Not(Box::new(parse_matcher(&list[1])?)))
        }
        "cond" => Ok(ArgMatcher::Cond(parse_cond_branches(list)?)),
        other => Err(format!("unknown matcher: {other}")),
    }
}

fn parse_pattern(sexpr: &Sexpr) -> Result<Pattern, String> {
    match sexpr {
        Sexpr::Atom(s) if s == "*" => Ok(Pattern::Literal("*".to_string())),
        Sexpr::Atom(s) => Ok(Pattern::Literal(s.clone())),
        Sexpr::List(list) => {
            if list.is_empty() {
                return Err("empty pattern form".into());
            }
            let tag = list[0].as_atom().ok_or("pattern form tag must be an atom")?;
            match tag {
                "regex" => {
                    if list.len() != 2 {
                        return Err("regex must have exactly one pattern".into());
                    }
                    let pat = list[1]
                        .as_atom()
                        .ok_or("regex pattern must be a string")?;
                    let re = regex::Regex::new(pat)
                        .map_err(|e| format!("invalid regex '{pat}': {e}"))?;
                    Ok(Pattern::Regex(re))
                }
                "or" => {
                    // Compile to regex: ^(a|b|c)$
                    let alternatives: Result<Vec<String>, _> = list[1..]
                        .iter()
                        .map(|s| {
                            s.as_atom()
                                .map(regex::escape)
                                .ok_or("or values must be strings".to_string())
                        })
                        .collect();
                    let pat = format!("^({})$", alternatives?.join("|"));
                    let re = regex::Regex::new(&pat)
                        .map_err(|e| format!("invalid or regex: {e}"))?;
                    Ok(Pattern::Regex(re))
                }
                other => Err(format!("unknown pattern form: {other}")),
            }
        }
    }
}

fn parse_wrapper(parts: &[Sexpr]) -> Result<Wrapper, String> {
    // (wrapper "nohup" after-flags)
    // (wrapper "mise" (positional "exec") (after "--"))
    if parts.is_empty() {
        return Err("wrapper must have a command name".into());
    }

    let command = parts[0]
        .as_atom()
        .ok_or("wrapper command must be a string")?
        .to_string();

    let mut positional_args = Vec::new();
    let mut kind = None;

    for part in &parts[1..] {
        match part {
            Sexpr::Atom(s) if s == "after-flags" => {
                kind = Some(WrapperKind::AfterFlags);
            }
            Sexpr::List(list) if !list.is_empty() => {
                let tag = list[0].as_atom().ok_or("wrapper element tag must be an atom")?;
                match tag {
                    "positional" => {
                        for item in &list[1..] {
                            positional_args.push(parse_pattern(item)?);
                        }
                    }
                    "after" => {
                        if list.len() != 2 {
                            return Err("after must have exactly one delimiter".into());
                        }
                        let delim = list[1]
                            .as_atom()
                            .ok_or("after delimiter must be a string")?
                            .to_string();
                        kind = Some(WrapperKind::AfterDelimiter(delim));
                    }
                    other => return Err(format!("unknown wrapper element: {other}")),
                }
            }
            _ => return Err("unexpected wrapper element".into()),
        }
    }

    Ok(Wrapper {
        command,
        positional_args,
        kind: kind.ok_or("wrapper must specify after-flags or (after ...)")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let config = parse("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.wrappers.is_empty());
        assert!(!config.security.blocked_paths.is_empty());
    }

    #[test]
    fn simple_allow_rule() {
        let config = parse(r#"(rule (command "cat") (effect :allow))"#).unwrap();
        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        assert_eq!(rule.decision, Some(Decision::Allow));
        assert!(rule.matcher.is_none());
        assert!(rule.reason.is_none());
    }

    #[test]
    fn deny_with_reason() {
        let config = parse(r#"(rule (command "rm") (effect :deny "dangerous"))"#).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.decision, Some(Decision::Deny));
        assert_eq!(rule.reason.as_deref(), Some("dangerous"));
    }

    #[test]
    fn ask_with_reason() {
        let config = parse(r#"(rule (command "curl") (effect :ask "network op"))"#).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.decision, Some(Decision::Ask));
        assert_eq!(rule.reason.as_deref(), Some("network op"));
    }

    #[test]
    fn command_or() {
        let config =
            parse(r#"(rule (command (or "cat" "ls" "grep")) (effect :allow))"#).unwrap();
        match &config.rules[0].command {
            CommandMatcher::List(v) => assert_eq!(v, &["cat", "ls", "grep"]),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn command_regex() {
        let config =
            parse(r#"(rule (command (regex "^git.*$")) (effect :allow))"#).unwrap();
        match &config.rules[0].command {
            CommandMatcher::Regex(re) => assert!(re.is_match("git-log")),
            _ => panic!("expected Regex"),
        }
    }

    /// Helper to extract the matcher from a rule.
    fn get_matcher(rule: &Rule) -> Option<&ArgMatcher> {
        rule.matcher.as_ref()
    }

    #[test]
    fn positional_matcher() {
        let config = parse(
            r#"(rule (command "git") (args (positional "status")) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pats) => {
                assert_eq!(pats.len(), 1);
                assert!(pats[0].is_match("status"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn positional_wildcard() {
        let config = parse(
            r#"(rule (command "aws") (args (positional * (regex "^get.*"))) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pats) => {
                assert!(pats[0].is_wildcard());
                assert!(pats[1].is_match("get-instances"));
                assert!(!pats[1].is_match("delete-instance"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn exact_matcher() {
        let config = parse(
            r#"(rule (command "git") (args (exact "remote")) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::ExactPositional(pats) => {
                assert_eq!(pats.len(), 1);
                assert!(pats[0].is_match("remote"));
            }
            _ => panic!("expected ExactPositional"),
        }
    }

    #[test]
    fn exact_matcher_with_wildcard() {
        let config = parse(
            r#"(rule (command "git") (args (exact * "show")) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::ExactPositional(pats) => {
                assert_eq!(pats.len(), 2);
                assert!(pats[0].is_wildcard());
                assert!(pats[1].is_match("show"));
            }
            _ => panic!("expected ExactPositional"),
        }
    }

    #[test]
    fn anywhere_matcher() {
        let config = parse(
            r#"(rule (command "curl") (args (anywhere "-I" "--head")) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Anywhere(pats) => {
                assert!(pats[0].is_match("-I"));
                assert!(pats[1].is_match("--head"));
            }
            _ => panic!("expected Anywhere"),
        }
    }

    #[test]
    fn forbidden_desugars_to_not_anywhere() {
        let config = parse(
            r#"(rule (command "curl") (args (forbidden "-d" "--data")) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Not(inner) => match inner.as_ref() {
                ArgMatcher::Anywhere(pats) => {
                    assert_eq!(pats.len(), 2);
                    assert!(pats[0].is_match("-d"));
                    assert!(pats[1].is_match("--data"));
                }
                _ => panic!("expected Anywhere inside Not"),
            },
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn and_matcher() {
        let config = parse(
            r#"(rule (command "rm")
                   (args (and (anywhere "-r" "--recursive")
                              (anywhere "/")))
                   (effect :deny "dangerous"))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::And(matchers) => {
                assert_eq!(matchers.len(), 2);
                assert!(matches!(&matchers[0], ArgMatcher::Anywhere(_)));
                assert!(matches!(&matchers[1], ArgMatcher::Anywhere(_)));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn or_matcher() {
        let config = parse(
            r#"(rule (command "gh")
                   (args (or (positional "repo" (or "create" "delete"))
                             (positional "secret" (or "set" "delete"))))
                   (effect :deny))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Or(matchers) => {
                assert_eq!(matchers.len(), 2);
                assert!(matches!(&matchers[0], ArgMatcher::Positional(_)));
                assert!(matches!(&matchers[1], ArgMatcher::Positional(_)));
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn not_matcher() {
        let config = parse(
            r#"(rule (command "curl") (args (not (anywhere "--force"))) (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Not(inner) => {
                assert!(matches!(inner.as_ref(), ArgMatcher::Anywhere(_)));
            }
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn or_pattern() {
        let config = parse(
            r#"(rule (command "gh")
                   (args (positional "repo" (or "create" "delete" "fork")))
                   (effect :deny))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pats) => {
                assert!(pats[0].is_match("repo"));
                assert!(pats[1].is_match("create"));
                assert!(pats[1].is_match("delete"));
                assert!(pats[1].is_match("fork"));
                assert!(!pats[1].is_match("view"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn regex_pattern() {
        let config = parse(
            r#"(rule (command "aws")
                   (args (positional * (regex "^(get|describe|list).*")))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pats) => {
                assert!(pats[0].is_wildcard());
                assert!(pats[1].is_match("get-object"));
                assert!(pats[1].is_match("describe-instances"));
                assert!(pats[1].is_match("list-buckets"));
                assert!(!pats[1].is_match("delete-object"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn examples_in_rule() {
        let config = parse(
            r#"(rule (command "curl")
                   (args (anywhere "-I"))
                   (effect :allow "HEAD request")
                   (example :allow "curl -I https://example.com")
                   (example :allow "curl --head https://example.com"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].examples.len(), 2);
        assert_eq!(
            config.rules[0].examples[0].command,
            "curl -I https://example.com"
        );
        assert_eq!(config.rules[0].examples[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].examples[1].expected, Decision::Allow);
    }

    #[test]
    fn wrapper_after_flags() {
        let config = parse(r#"(wrapper "nohup" after-flags)"#).unwrap();
        assert_eq!(config.wrappers.len(), 1);
        assert_eq!(config.wrappers[0].command, "nohup");
        assert!(matches!(config.wrappers[0].kind, WrapperKind::AfterFlags));
        assert!(config.wrappers[0].positional_args.is_empty());
    }

    #[test]
    fn wrapper_after_delimiter() {
        let config = parse(
            r#"(wrapper "mise" (positional "exec") (after "--"))"#,
        )
        .unwrap();
        assert_eq!(config.wrappers[0].command, "mise");
        match &config.wrappers[0].kind {
            WrapperKind::AfterDelimiter(d) => assert_eq!(d, "--"),
            _ => panic!("expected AfterDelimiter"),
        }
        assert_eq!(config.wrappers[0].positional_args.len(), 1);
        assert!(config.wrappers[0].positional_args[0].is_match("exec"));
    }

    #[test]
    fn blocked_paths() {
        let config = parse(
            r#"(blocked-paths "\\.secret/" "^/private/")"#,
        )
        .unwrap();
        let patterns: Vec<&str> = config
            .security
            .blocked_paths
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert!(patterns.contains(&"\\.secret/"));
        assert!(patterns.contains(&"^/private/"));
        assert!(patterns.iter().any(|p| p.contains(".env")));
    }

    #[test]
    fn blocked_paths_no_duplicates() {
        let config = parse(
            r#"(blocked-paths "(^|/)\\.env($|[./])")"#,
        )
        .unwrap();
        assert_eq!(config.security.blocked_paths.len(), 10);
    }

    #[test]
    fn full_config() {
        let input = r#"
            (rule (command "rm")
                  (args (and (anywhere "-r" "--recursive")
                             (anywhere "/")))
                  (effect :deny "Recursive deletion from root"))

            (rule (command (or "cat" "ls" "grep"))
                  (effect :allow))

            (rule (command "aws")
                  (args (positional * (regex "^(get|describe|list).*")))
                  (effect :allow))

            (wrapper "nohup" after-flags)
            (wrapper "mise" (positional "exec") (after "--"))

            (blocked-paths "\\.env" "\\.ssh/")
        "#;
        let config = parse(input).unwrap();
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.wrappers.len(), 2);
        assert!(config.security.blocked_paths.len() >= 10);
    }

    // ── Error cases ────────────────────────────────────────────────────

    #[test]
    fn error_top_level_atom() {
        assert!(parse("hello").is_err());
    }

    #[test]
    fn error_empty_form() {
        assert!(parse("()").is_err());
    }

    #[test]
    fn error_unknown_form() {
        assert!(parse(r#"(bogus "foo")"#).is_err());
    }

    #[test]
    fn error_rule_missing_command() {
        assert!(parse(r#"(rule (effect :allow))"#).is_err());
    }

    #[test]
    fn error_rule_missing_decision() {
        assert!(parse(r#"(rule (command "cat"))"#).is_err());
    }

    #[test]
    fn error_unknown_rule_element() {
        assert!(parse(r#"(rule (command "cat") (effect :allow) (bogus))"#).is_err());
    }

    #[test]
    fn error_unknown_matcher() {
        assert!(parse(
            r#"(rule (command "cat") (args (bogus "x")) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_unknown_command_form() {
        assert!(parse(r#"(rule (command (bogus "x")) (effect :allow))"#).is_err());
    }

    #[test]
    fn error_invalid_regex_pattern() {
        assert!(parse(
            r#"(rule (command "git") (args (positional (regex "^[invalid"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_invalid_command_regex() {
        assert!(parse(r#"(rule (command (regex "^[invalid")) (effect :allow))"#).is_err());
    }

    #[test]
    fn error_wrapper_missing_kind() {
        assert!(parse(r#"(wrapper "nohup")"#).is_err());
    }

    #[test]
    fn error_wrapper_missing_command() {
        assert!(parse(r#"(wrapper)"#).is_err());
    }

    #[test]
    fn error_blocked_paths_invalid_regex() {
        assert!(parse(r#"(blocked-paths "^[invalid")"#).is_err());
    }

    #[test]
    fn error_unknown_expected_in_example() {
        assert!(parse(
            r#"(rule (command "cat") (effect :allow) (example :maybe "cat foo"))"#
        )
        .is_err());
    }

    #[test]
    fn error_not_with_multiple_matchers() {
        assert!(parse(
            r#"(rule (command "x") (args (not (anywhere "a") (anywhere "b"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_unknown_pattern_form() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (bogus "a"))) (effect :allow))"#
        )
        .is_err());
    }

    // ── Error branches for uncovered validation paths ─────────────────

    #[test]
    fn error_empty_rule_element() {
        assert!(parse(r#"(rule () (command "cat") (effect :allow))"#).is_err());
    }

    #[test]
    fn error_command_wrong_arity() {
        assert!(parse(r#"(rule (command "cat" "dog") (effect :allow))"#).is_err());
    }

    #[test]
    fn error_args_wrong_arity() {
        assert!(parse(
            r#"(rule (command "cat") (args (anywhere "x") (anywhere "y")) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_effect_missing_keyword() {
        assert!(parse(r#"(rule (command "cat") (effect))"#).is_err());
    }

    #[test]
    fn error_unknown_effect_keyword() {
        assert!(parse(r#"(rule (command "cat") (effect :yolo))"#).is_err());
    }

    #[test]
    fn error_example_too_few_parts() {
        assert!(parse(r#"(rule (command "cat") (effect :allow) (example :allow))"#).is_err());
    }

    #[test]
    fn error_empty_command_form() {
        assert!(parse(r#"(rule (command ()) (effect :allow))"#).is_err());
    }

    #[test]
    fn error_regex_command_wrong_arity() {
        assert!(parse(r#"(rule (command (regex "a" "b")) (effect :allow))"#).is_err());
    }

    #[test]
    fn error_empty_matcher() {
        assert!(parse(r#"(rule (command "cat") (args ()) (effect :allow))"#).is_err());
    }

    #[test]
    fn error_empty_pattern_form() {
        assert!(parse(
            r#"(rule (command "cat") (args (positional ())) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_regex_pattern_wrong_arity() {
        assert!(parse(
            r#"(rule (command "cat") (args (positional (regex "a" "b"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_after_wrong_arity() {
        assert!(parse(r#"(wrapper "x" (after "--" "extra"))"#).is_err());
    }

    #[test]
    fn error_unknown_wrapper_element() {
        assert!(parse(r#"(wrapper "x" (bogus "y"))"#).is_err());
    }

    #[test]
    fn error_unexpected_wrapper_element() {
        // bare atom that isn't "after-flags"
        assert!(parse(r#"(wrapper "x" something-else)"#).is_err());
    }

    // ── Integration with engine ────────────────────────────────────────

    #[test]
    fn config_evaluates_correctly() {
        use crate::engine;

        let config = parse(
            r#"
            (rule (command "rm")
                  (args (and (anywhere "-r" "--recursive")
                             (anywhere "/")))
                  (effect :deny "Recursive deletion from root"))

            (rule (command "rm")
                  (effect :allow))

            (rule (command "curl")
                  (args (forbidden "-d" "--data" "-F" "--form" "-X" "--request"))
                  (effect :allow "GET request"))

            (rule (command "curl")
                  (effect :ask "Network operation"))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("rm file.txt", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("rm -rf /", &config).decision, Decision::Deny);
        assert_eq!(
            engine::evaluate("curl https://example.com", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            engine::evaluate("curl -d data https://example.com", &config).decision,
            Decision::Ask
        );
    }

    #[test]
    fn exact_vs_positional_evaluates_correctly() {
        use crate::engine;

        let config = parse(
            r#"
            (rule (command "git")
                  (args (exact "remote"))
                  (effect :allow "bare remote"))

            (rule (command "git")
                  (args (positional "remote"))
                  (effect :ask "remote subcommand"))
            "#,
        )
        .unwrap();

        // Exactly "git remote" → allow (exact matches)
        assert_eq!(
            engine::evaluate("git remote", &config).decision,
            Decision::Allow
        );
        // "git remote add origin url" → ask (exact rejects, positional matches)
        assert_eq!(
            engine::evaluate("git remote add origin url", &config).decision,
            Decision::Ask
        );
    }

    // ── safe-env-vars parsing ──────────────────────────────────────────

    #[test]
    fn safe_env_vars_basic() {
        let config = parse(r#"(safe-env-vars "HOME" "PWD" "USER")"#).unwrap();
        assert!(config.security.safe_env_vars.contains("HOME"));
        assert!(config.security.safe_env_vars.contains("PWD"));
        assert!(config.security.safe_env_vars.contains("USER"));
        assert_eq!(config.security.safe_env_vars.len(), 3);
    }

    #[test]
    fn safe_env_vars_empty() {
        let config = parse(r#"(safe-env-vars)"#).unwrap();
        assert!(config.security.safe_env_vars.is_empty());
    }

    #[test]
    fn safe_env_vars_with_other_config() {
        let input = r#"
            (safe-env-vars "HOME" "EDITOR")
            (rule (command "ls") (effect :allow))
            (blocked-paths "\\.secret/")
        "#;
        let config = parse(input).unwrap();
        assert_eq!(config.security.safe_env_vars.len(), 2);
        assert!(config.security.safe_env_vars.contains("HOME"));
        assert!(config.security.safe_env_vars.contains("EDITOR"));
        assert_eq!(config.rules.len(), 1);
        assert!(config.security.blocked_paths.len() > 10); // defaults + custom
    }

    // ── cond parsing ──────────────────────────────────────────────────

    #[test]
    fn cond_basic() {
        let config = parse(
            r#"(rule (command "tmux")
                  (args (cond
                    ((positional "source-file" (or "~/.config/tmux/custom.conf"
                                                   "~/.config/tmux/tmux.conf"))
                     (effect :allow "Reloading config is safe"))
                    (_ (effect :deny "Unknown tmux source-file")))))"#,
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 2);
                assert!(branches[0].matcher.is_some());
                assert_eq!(branches[0].decision, Decision::Allow);
                assert_eq!(branches[0].reason.as_deref(), Some("Reloading config is safe"));
                assert!(branches[1].matcher.is_none()); // wildcard
                assert_eq!(branches[1].decision, Decision::Deny);
            }
            _ => panic!("expected Cond"),
        }
        assert!(config.rules[0].decision.is_none());
    }

    #[test]
    fn cond_t_wildcard() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (cond
                    ((positional "bar") (effect :allow))
                    (t (effect :deny)))))"#,
        )
        .unwrap();
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 2);
                assert!(branches[1].matcher.is_none()); // t is wildcard
            }
            _ => panic!("expected Cond"),
        }
    }

    #[test]
    fn cond_with_examples() {
        let config = parse(
            r#"(rule (command "tmux")
                  (args (cond
                    ((positional "source-file" "~/.config/tmux/tmux.conf")
                     (effect :allow "Reloading config"))
                    (_ (effect :deny "Unknown tmux command"))))
                  (example :allow "tmux source-file ~/.config/tmux/tmux.conf")
                  (example :deny "tmux source-file /tmp/evil.conf"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].examples.len(), 2);
        assert_eq!(config.rules[0].examples[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].examples[1].expected, Decision::Deny);
    }

    #[test]
    fn cond_plus_effect_is_error() {
        assert!(parse(
            r#"(rule (command "x") (args (cond (_ (effect :allow)))) (effect :deny))"#
        )
        .is_err());
    }

    #[test]
    fn error_cond_empty() {
        assert!(parse(r#"(rule (command "x") (args (cond)))"#).is_err());
    }

    #[test]
    fn error_cond_branch_missing_effect() {
        assert!(parse(
            r#"(rule (command "x") (args (cond ((positional "y")))))"#
        )
        .is_err());
    }

    #[test]
    fn error_cond_empty_branch() {
        assert!(parse(r#"(rule (command "x") (args (cond ())))"#).is_err());
    }

    #[test]
    fn error_cond_empty_branch_condition() {
        assert!(parse(r#"(rule (command "x") (args (cond (() (effect :allow)))))"#).is_err());
    }

    #[test]
    fn error_cond_non_args_condition() {
        assert!(parse(
            r#"(rule (command "x") (args (cond ((bogus "y") (effect :allow)))))"#
        )
        .is_err());
    }

    #[test]
    fn error_cond_empty_branch_element() {
        assert!(parse(r#"(rule (command "x") (args (cond (_ ()))))"#).is_err());
    }

    #[test]
    fn error_cond_unknown_branch_element() {
        assert!(parse(
            r#"(rule (command "x") (args (cond (_ (bogus "y")))))"#
        )
        .is_err());
    }

    #[test]
    fn error_no_effect_and_no_cond() {
        assert!(parse(
            r#"(rule (command "x") (args (positional "y")))"#
        )
        .is_err());
    }

    #[test]
    fn error_old_rule_level_cond_is_unknown() {
        assert!(parse(
            r#"(rule (command "x") (cond (_ (effect :allow))))"#
        )
        .is_err());
    }

    #[test]
    fn cond_nested_in_and_with_effect() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (and (cond
                               ((positional "bar") (effect :allow))
                               (_ (effect :deny)))
                             (anywhere "--verbose")))
                  (effect :allow "verbose bar"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].decision, Some(Decision::Allow));
        match &config.rules[0].matcher {
            Some(ArgMatcher::And(matchers)) => {
                assert_eq!(matchers.len(), 2);
                assert!(matches!(&matchers[0], ArgMatcher::Cond(_)));
                assert!(matches!(&matchers[1], ArgMatcher::Anywhere(_)));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn or_matcher_evaluates_correctly() {
        use crate::engine;

        let config = parse(
            r#"
            (rule (command "gh")
                  (args (or (positional "repo" (or "create" "delete"))
                            (positional "secret" (or "set" "delete"))))
                  (effect :deny "Supply chain attack"))

            (rule (command "gh")
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(
            engine::evaluate("gh repo delete foo", &config).decision,
            Decision::Deny
        );
        assert_eq!(
            engine::evaluate("gh secret set FOO", &config).decision,
            Decision::Deny
        );
        assert_eq!(engine::evaluate("gh pr list", &config).decision, Decision::Allow);
        assert_eq!(
            engine::evaluate("gh repo view foo", &config).decision,
            Decision::Allow
        );
    }
}

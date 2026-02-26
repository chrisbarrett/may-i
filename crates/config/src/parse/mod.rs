// Configuration parsing — R10, R10a–R10f
// S-expression configuration for authorization rules, wrappers, and security.

mod expr;
use expr::{parse_expr, parse_pos_expr};

use may_i_core::ConfigError;
use may_i_sexpr::{RawError, Span, Sexpr};
use may_i_core::{
    ArgMatcher, Check, CommandMatcher, CondArm, CondBranch, Config, Decision, Effect, Expr,
    PosExpr, Rule, RuleBody, SecurityConfig, SourceInfo, Wrapper, WrapperStep,
};

/// Parse an s-expression config string into Config.
///
/// `filename` is used in diagnostic messages to identify the source file.
pub fn parse(input: &str, filename: &str) -> Result<Config, Box<ConfigError>> {
    let mut config =
        parse_raw(input).map_err(|raw| Box::new(ConfigError::from_raw(raw, input, filename)))?;
    config.source_info = Some(SourceInfo {
        filename: filename.to_string(),
        content: input.to_string(),
    });
    Ok(config)
}

fn parse_raw(input: &str) -> Result<Config, RawError> {
    let (forms, errors) = may_i_sexpr::parse(input);
    if let Some(err) = errors.into_iter().next() {
        return Err(err);
    }
    let mut rules = Vec::new();
    let mut wrappers = Vec::new();
    let mut security = SecurityConfig::default();

    for form in &forms {
        let list = form.as_list().ok_or_else(|| {
            RawError::new("top-level form must be a list", form.span())
                .with_label("expected a parenthesised form")
        })?;
        if list.is_empty() {
            return Err(RawError::new("empty top-level form", form.span()));
        }
        let tag = list[0].as_atom().ok_or_else(|| {
            RawError::new("form tag must be an atom", list[0].span())
        })?;
        match tag {
            "rule" => rules.push(parse_rule(&list[1..], form.span())?),
            "wrapper" => wrappers.push(parse_wrapper(&list[1..], form.span())?),
            "blocked-paths" => {
                return Err(RawError::new(
                    "blocked-paths is no longer supported; use the filesystem sandbox system provided by your OS",
                    form.span(),
                )
                .with_help("remove the (blocked-paths ...) form from your config"));
            }
            "safe-env-vars" => {
                for item in &list[1..] {
                    let s = item.as_atom().ok_or_else(|| {
                        RawError::new("safe-env-vars entry must be a string", item.span())
                    })?;
                    security.safe_env_vars.insert(s.to_string());
                }
            }
            other => {
                return Err(RawError::new(
                    format!("unknown top-level form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised form")
                .with_help("valid top-level forms: rule, wrapper, safe-env-vars"));
            }
        }
    }

    Ok(Config {
        rules,
        wrappers,
        security,
        source_info: None,
    })
}

fn parse_effect(list: &[Sexpr]) -> Result<Effect, RawError> {
    if list.len() < 2 {
        let span = list.first().map_or(Span::new(0, 0), |s| s.span());
        return Err(RawError::new(
            "effect must have a keyword (:allow, :deny, or :ask)",
            span,
        ));
    }
    let kw = list[1].as_atom().ok_or_else(|| {
        RawError::new("effect keyword must be an atom", list[1].span())
    })?;
    let decision = match kw {
        ":allow" => Decision::Allow,
        ":deny" => Decision::Deny,
        ":ask" => Decision::Ask,
        other => {
            return Err(RawError::new(
                format!("unknown effect keyword: {other}"),
                list[1].span(),
            )
            .with_label("not a valid effect keyword")
            .with_help("valid effect keywords: :allow, :deny, :ask"));
        }
    };
    let reason = if list.len() > 2 {
        Some(
            list[2]
                .as_atom()
                .ok_or_else(|| {
                    RawError::new("reason must be a string", list[2].span())
                })?
                .to_string(),
        )
    } else {
        None
    };
    Ok(Effect { decision, reason })
}

/// Generic cond branch parser. The `parse_test` closure parses the test
/// element (returning `None` for `else` catch-all branches).
fn parse_cond_branches_generic<T>(
    branches: &[Sexpr],
    cond_span: Span,
    parse_test: impl Fn(&Sexpr) -> Result<T, RawError>,
    make_else: impl Fn() -> T,
) -> Result<Vec<(T, Effect)>, RawError> {
    if branches.is_empty() {
        return Err(RawError::new("cond must have at least one branch", cond_span));
    }
    let mut result = Vec::new();
    for branch in branches {
        let items = branch.as_list().ok_or_else(|| {
            RawError::new("cond branch must be a list", branch.span())
        })?;
        if items.is_empty() {
            return Err(RawError::new("empty cond branch", branch.span()));
        }
        let test = match &items[0] {
            Sexpr::Atom(s, _) if s == "else" => make_else(),
            other => parse_test(other)?,
        };
        let mut effect = None;
        for item in &items[1..] {
            let il = item.as_list().ok_or_else(|| {
                RawError::new("cond branch element must be a list", item.span())
            })?;
            if il.is_empty() {
                return Err(RawError::new("empty cond branch element", item.span()));
            }
            let tag = il[0].as_atom().ok_or_else(|| {
                RawError::new("cond branch element tag must be an atom", il[0].span())
            })?;
            if tag == "effect" {
                effect = Some(parse_effect(il)?);
            } else {
                return Err(RawError::new(
                    format!("unknown cond branch element: {tag}"),
                    il[0].span(),
                ));
            }
        }
        result.push((
            test,
            effect.ok_or_else(|| {
                RawError::new("cond branch must have an effect", branch.span())
            })?,
        ));
    }
    Ok(result)
}

fn parse_cond_branches(list: &[Sexpr]) -> Result<CondArm, RawError> {
    let pairs = parse_cond_branches_generic(
        &list[1..],
        list[0].span(),
        |s| parse_matcher(s).map(Some),
        || None,
    )?;
    let mut branches = Vec::new();
    let mut fallback = None;
    for (matcher, effect) in pairs {
        match matcher {
            Some(m) => branches.push(CondBranch { matcher: m, effect }),
            None => fallback = Some(effect),
        }
    }
    Ok(CondArm { branches, fallback })
}

/// Shared helper: parse `(if TEST EFFECT EFFECT?)` sugar.
/// `parse_test` parses the test expression from an s-expression.
/// Returns pairs of (test, effect) where the else branch has `None` for its test.
fn parse_if_sugar<T>(
    args: &[Sexpr],
    form_span: Span,
    parse_test: impl Fn(&Sexpr) -> Result<T, RawError>,
) -> Result<(T, Effect, Option<Effect>), RawError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(RawError::new(
            "if must have 2 or 3 arguments: (if TEST EFFECT EFFECT?)",
            form_span,
        ));
    }
    let test = parse_test(&args[0])?;
    let then_list = args[1].as_list().ok_or_else(|| {
        RawError::new("if then-branch must be an effect list", args[1].span())
    })?;
    let then_effect = parse_effect(then_list)?;

    let else_effect = if args.len() == 3 {
        let else_list = args[2].as_list().ok_or_else(|| {
            RawError::new("if else-branch must be an effect list", args[2].span())
        })?;
        Some(parse_effect(else_list)?)
    } else {
        None
    };

    Ok((test, then_effect, else_effect))
}

/// Shared helper: parse `(when TEST EFFECT)` / `(unless TEST EFFECT)` sugar.
fn parse_unary_sugar<T>(
    name: &str,
    args: &[Sexpr],
    form_span: Span,
    parse_test: impl Fn(&Sexpr) -> Result<T, RawError>,
) -> Result<(T, Effect), RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            format!("{name} must have exactly 2 arguments: ({name} TEST EFFECT)"),
            form_span,
        ));
    }
    let test = parse_test(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new(format!("{name} effect must be an effect list"), args[1].span())
    })?;
    let effect = parse_effect(effect_list)?;
    Ok((test, effect))
}

fn parse_matcher_if_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    let (test, then_effect, else_effect) = parse_if_sugar(args, form_span, parse_matcher)?;
    Ok(ArgMatcher::Cond(CondArm {
        branches: vec![CondBranch { matcher: test, effect: then_effect }],
        fallback: else_effect,
    }))
}

fn parse_matcher_when_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    let (test, effect) = parse_unary_sugar("when", args, form_span, parse_matcher)?;
    Ok(ArgMatcher::Cond(CondArm {
        branches: vec![CondBranch { matcher: test, effect }],
        fallback: None,
    }))
}

fn parse_matcher_unless_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    let (test, effect) = parse_unary_sugar("unless", args, form_span, parse_matcher)?;
    Ok(ArgMatcher::Cond(CondArm {
        branches: vec![CondBranch { matcher: ArgMatcher::Not(Box::new(test)), effect }],
        fallback: None,
    }))
}

fn parse_rule(parts: &[Sexpr], rule_span: Span) -> Result<Rule, RawError> {
    let mut command = None;
    let mut matcher = None;
    let mut effect = None;
    let mut checks = Vec::new();

    for part in parts {
        let list = part.as_list().ok_or_else(|| {
            RawError::new("rule element must be a list", part.span())
        })?;
        if list.is_empty() {
            return Err(RawError::new("empty rule element", part.span()));
        }
        let tag = list[0].as_atom().ok_or_else(|| {
            RawError::new("rule element tag must be an atom", list[0].span())
        })?;
        match tag {
            "command" => {
                if list.len() != 2 {
                    return Err(RawError::new(
                        "command must have exactly one value",
                        part.span(),
                    ));
                }
                command = Some(parse_command(&list[1])?);
            }
            "args" => {
                if list.len() != 2 {
                    return Err(RawError::new(
                        "args must have exactly one matcher",
                        part.span(),
                    ));
                }
                matcher = Some(parse_matcher(&list[1])?);
            }
            "effect" => {
                effect = Some(parse_effect(list)?);
            }
            "check" => {
                let pairs = &list[1..];
                if pairs.len() < 2 || pairs.len() % 2 != 0 {
                    return Err(RawError::new(
                        "check must have 1+ paired :decision \"command\" entries",
                        part.span(),
                    ));
                }
                for pair in pairs.chunks(2) {
                    let expected = match pair[0]
                        .as_atom()
                        .ok_or_else(|| {
                            RawError::new("check decision must be an atom", pair[0].span())
                        })? {
                        ":allow" => Decision::Allow,
                        ":deny" => Decision::Deny,
                        ":ask" => Decision::Ask,
                        other => {
                            return Err(RawError::new(
                                format!("unknown expected decision: {other}"),
                                pair[0].span(),
                            )
                            .with_label("not a valid decision")
                            .with_help("valid decisions: :allow, :deny, :ask"));
                        }
                    };
                    let cmd = pair[1]
                        .as_atom()
                        .ok_or_else(|| {
                            RawError::new("check command must be a string", pair[1].span())
                        })?;
                    checks.push(Check {
                        command: cmd.to_string(),
                        expected,
                        source_span: pair[1].span(),
                    });
                }
            }
            other => {
                return Err(RawError::new(
                    format!("unknown rule element: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised rule element")
                .with_help("valid rule elements: command, args, effect, check"));
            }
        }
    }

    // Build body: embedded effects (top-level cond or Expr::Cond) vs explicit effect
    let has_embedded_effect = matcher.as_ref().is_some_and(|m| {
        matches!(m, ArgMatcher::Cond(_)) || m.has_effect()
    });
    let body = match (has_embedded_effect, matcher, effect) {
        (true, _, Some(_)) => {
            return Err(RawError::new(
                "cond and effect are mutually exclusive in a rule",
                rule_span,
            ));
        }
        (true, Some(m), None) => RuleBody::Branching(m),
        (false, matcher, Some(effect)) => RuleBody::Effect { matcher, effect },
        (_, None, None) | (false, Some(_), None) => {
            return Err(RawError::new(
                "rule must have an effect (or a top-level cond matcher)",
                rule_span,
            ));
        }
    };

    Ok(Rule {
        command: command.ok_or_else(|| {
            RawError::new("rule must have a command", rule_span)
        })?,
        body,
        checks,
        source_span: rule_span,
    })
}

fn parse_command(sexpr: &Sexpr) -> Result<CommandMatcher, RawError> {
    match sexpr {
        Sexpr::Atom(s, _) => Ok(CommandMatcher::Exact(s.clone())),
        Sexpr::List(list, span) => {
            if list.is_empty() {
                return Err(RawError::new("empty command form", *span));
            }
            let tag = list[0].as_atom().ok_or_else(|| {
                RawError::new("command form tag must be an atom", list[0].span())
            })?;
            match tag {
                "or" => {
                    let names: Result<Vec<String>, _> = list[1..]
                        .iter()
                        .map(|s| {
                            s.as_atom()
                                .map(|s| s.to_string())
                                .ok_or_else(|| {
                                    RawError::new("or values must be strings", s.span())
                                })
                        })
                        .collect();
                    Ok(CommandMatcher::List(names?))
                }
                "regex" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "regex must have exactly one pattern",
                            *span,
                        ));
                    }
                    let pat = list[1]
                        .as_atom()
                        .ok_or_else(|| {
                            RawError::new("regex pattern must be a string", list[1].span())
                        })?;
                    let re = regex::Regex::new(pat).map_err(|e| {
                        RawError::new(
                            format!("invalid command regex: {e}"),
                            list[1].span(),
                        )
                    })?;
                    Ok(CommandMatcher::Regex(re))
                }
                other => Err(RawError::new(
                    format!("unknown command form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised command form")
                .with_help("valid command forms: or, regex")),
            }
        }
    }
}

fn parse_matcher(sexpr: &Sexpr) -> Result<ArgMatcher, RawError> {
    let list = sexpr.as_list().ok_or_else(|| {
        RawError::new("matcher must be a list", sexpr.span())
    })?;
    if list.is_empty() {
        return Err(RawError::new("empty matcher", sexpr.span()));
    }
    let tag = list[0].as_atom().ok_or_else(|| {
        RawError::new("matcher tag must be an atom", list[0].span())
    })?;
    match tag {
        "positional" => {
            let pexprs: Result<Vec<PosExpr>, _> =
                list[1..].iter().map(parse_pos_expr).collect();
            Ok(ArgMatcher::Positional(pexprs?))
        }
        "exact" => {
            let pexprs: Result<Vec<PosExpr>, _> =
                list[1..].iter().map(parse_pos_expr).collect();
            Ok(ArgMatcher::ExactPositional(pexprs?))
        }
        "anywhere" => {
            let exprs: Result<Vec<Expr>, _> =
                list[1..].iter().map(parse_expr).collect();
            Ok(ArgMatcher::Anywhere(exprs?))
        }
        "forbidden" => {
            let exprs: Result<Vec<Expr>, _> =
                list[1..].iter().map(parse_expr).collect();
            Ok(ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(exprs?))))
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
                return Err(RawError::new(
                    "not must have exactly one matcher",
                    sexpr.span(),
                ));
            }
            Ok(ArgMatcher::Not(Box::new(parse_matcher(&list[1])?)))
        }
        "cond" => Ok(ArgMatcher::Cond(parse_cond_branches(list)?)),
        "if" => parse_matcher_if_form(&list[1..], sexpr.span()),
        "when" => parse_matcher_when_form(&list[1..], sexpr.span()),
        "unless" => parse_matcher_unless_form(&list[1..], sexpr.span()),
        other => Err(RawError::new(
            format!("unknown matcher: {other}"),
            list[0].span(),
        )
        .with_label("not a recognised matcher type")
        .with_help(
            "valid matchers: positional, exact, anywhere, forbidden, and, or, not, cond, if, when, unless",
        )),
    }
}


fn is_capture_keyword(s: &str) -> bool {
    matches!(s, ":command+args" | ":command" | ":args")
}

fn parse_wrapper(parts: &[Sexpr], wrapper_span: Span) -> Result<Wrapper, RawError> {
    // (wrapper "ssh"        (positional * :command+args))
    // (wrapper "nix"        (positional (or "shell" "develop")) (flag "--command" :command+args))
    // (wrapper "terragrunt" (flag "--" :command+args))
    // (wrapper "mise"       (positional "exec") (flag "--" :command+args))
    // (wrapper "nohup"      :command+args)                     ; shorthand
    if parts.is_empty() {
        return Err(RawError::new(
            "wrapper must have a command name",
            wrapper_span,
        ));
    }

    let command = parts[0]
        .as_atom()
        .ok_or_else(|| RawError::new("wrapper command must be a string", parts[0].span()))?
        .to_string();

    if parts[1..].is_empty() {
        return Err(RawError::new(
            "wrapper must have at least one step with a capture keyword (:command+args, :command, or :args)",
            wrapper_span,
        ));
    }

    let mut steps = Vec::new();
    let mut has_capture = false;

    for part in &parts[1..] {
        match part {
            // Bare capture keyword: (wrapper "nohup" :command+args)
            Sexpr::Atom(s, span) => {
                if is_capture_keyword(s) {
                    if has_capture {
                        return Err(RawError::new(
                            "wrapper has more than one capture keyword",
                            *span,
                        ));
                    }
                    steps.push(WrapperStep::Positional {
                        patterns: vec![],
                        capture: true,
                    });
                    has_capture = true;
                } else {
                    return Err(RawError::new(
                        format!("unexpected atom in wrapper: {s}"),
                        *span,
                    )
                    .with_label("not a recognised wrapper element")
                    .with_help(
                        "valid wrapper elements: (positional ...), (flag ...), :command+args, :command, :args",
                    ));
                }
            }

            Sexpr::List(list, span) if !list.is_empty() => {
                let tag = list[0].as_atom().ok_or_else(|| {
                    RawError::new("wrapper element tag must be an atom", list[0].span())
                })?;
                match tag {
                    "positional" => {
                        // Last element may be a capture keyword.
                        let (pattern_items, capture) =
                            match list[1..].last().and_then(|s| s.as_atom()).filter(|s| is_capture_keyword(s)) {
                                Some(_) => (&list[1..list.len() - 1], true),
                                None => (&list[1..], false),
                            };
                        if capture {
                            if has_capture {
                                return Err(RawError::new(
                                    "wrapper has more than one capture keyword",
                                    *span,
                                ));
                            }
                            has_capture = true;
                        }
                        let mut patterns = Vec::new();
                        for item in pattern_items {
                            patterns.push(parse_expr(item)?);
                        }
                        steps.push(WrapperStep::Positional { patterns, capture });
                    }
                    "flag" => {
                        if list.len() != 3 {
                            return Err(RawError::new(
                                "(flag ...) must have exactly a name and a capture keyword",
                                *span,
                            )
                            .with_help("example: (flag \"--\" :command+args)"));
                        }
                        let name = list[1]
                            .as_atom()
                            .ok_or_else(|| {
                                RawError::new("flag name must be a string", list[1].span())
                            })?
                            .to_string();
                        let capture_str = list[2].as_atom().ok_or_else(|| {
                            RawError::new(
                                "second element of (flag ...) must be a capture keyword",
                                list[2].span(),
                            )
                        })?;
                        if !is_capture_keyword(capture_str) {
                            return Err(RawError::new(
                                format!("unknown capture keyword: {capture_str}"),
                                list[2].span(),
                            )
                            .with_help("valid capture keywords: :command+args, :command, :args"));
                        }
                        if has_capture {
                            return Err(RawError::new(
                                "wrapper has more than one capture keyword",
                                *span,
                            ));
                        }
                        has_capture = true;
                        steps.push(WrapperStep::Flag { name });
                    }
                    other => {
                        return Err(RawError::new(
                            format!("unknown wrapper element: {other}"),
                            list[0].span(),
                        )
                        .with_label("not a recognised wrapper element")
                        .with_help("valid wrapper elements: positional, flag"));
                    }
                }
            }
            _ => {
                return Err(RawError::new("unexpected wrapper element", part.span()));
            }
        }
    }

    if !has_capture {
        return Err(RawError::new(
            "wrapper has no capture keyword; add :command+args, :command, or :args to indicate the inner command",
            wrapper_span,
        ));
    }

    Ok(Wrapper { command, steps })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper that passes a placeholder filename.
    fn parse(input: &str) -> Result<Config, Box<ConfigError>> {
        super::parse(input, "<test>")
    }

    #[test]
    fn empty_config() {
        let config = parse("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.wrappers.is_empty());
        assert!(config.security.safe_env_vars.is_empty());
    }

    #[test]
    fn simple_allow_rule() {
        let config = parse(r#"(rule (command "cat") (effect :allow))"#).unwrap();
        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        match &rule.body {
            RuleBody::Effect { matcher, effect } => {
                assert_eq!(effect.decision, Decision::Allow);
                assert!(matcher.is_none());
                assert!(effect.reason.is_none());
            }
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn deny_with_reason() {
        let config = parse(r#"(rule (command "rm") (effect :deny "dangerous"))"#).unwrap();
        let rule = &config.rules[0];
        match &rule.body {
            RuleBody::Effect { effect, .. } => {
                assert_eq!(effect.decision, Decision::Deny);
                assert_eq!(effect.reason.as_deref(), Some("dangerous"));
            }
            _ => panic!("expected Effect"),
        }
    }

    #[test]
    fn ask_with_reason() {
        let config = parse(r#"(rule (command "curl") (effect :ask "network op"))"#).unwrap();
        let rule = &config.rules[0];
        match &rule.body {
            RuleBody::Effect { effect, .. } => {
                assert_eq!(effect.decision, Decision::Ask);
                assert_eq!(effect.reason.as_deref(), Some("network op"));
            }
            _ => panic!("expected Effect"),
        }
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
        match &rule.body {
            RuleBody::Effect { matcher, .. } => matcher.as_ref(),
            RuleBody::Branching(m) => Some(m),
        }
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
    fn checks_in_rule() {
        let config = parse(
            r#"(rule (command "curl")
                   (args (anywhere "-I"))
                   (effect :allow "HEAD request")
                   (check :allow "curl -I https://example.com"
                          :allow "curl --head https://example.com"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].checks.len(), 2);
        assert_eq!(
            config.rules[0].checks[0].command,
            "curl -I https://example.com"
        );
        assert_eq!(config.rules[0].checks[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].checks[1].expected, Decision::Allow);
    }

    #[test]
    fn wrapper_bare_capture_keyword() {
        // (wrapper "nohup" :command+args) — shorthand for after-flags style
        let config = parse(r#"(wrapper "nohup" :command+args)"#).unwrap();
        assert_eq!(config.wrappers.len(), 1);
        assert_eq!(config.wrappers[0].command, "nohup");
        assert_eq!(config.wrappers[0].steps.len(), 1);
        match &config.wrappers[0].steps[0] {
            WrapperStep::Positional { patterns, capture } => {
                assert!(patterns.is_empty());
                assert!(capture);
            }
            other => panic!("expected Positional step, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_positional_capture() {
        // (wrapper "nohup" (positional :command+args)) — explicit form
        let config = parse(r#"(wrapper "nohup" (positional :command+args))"#).unwrap();
        assert_eq!(config.wrappers[0].steps.len(), 1);
        match &config.wrappers[0].steps[0] {
            WrapperStep::Positional { patterns, capture } => {
                assert!(patterns.is_empty());
                assert!(capture);
            }
            other => panic!("expected Positional step, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_ssh_style() {
        // (wrapper "ssh" (positional * :command+args))
        let config = parse(r#"(wrapper "ssh" (positional * :command+args))"#).unwrap();
        assert_eq!(config.wrappers[0].command, "ssh");
        match &config.wrappers[0].steps[0] {
            WrapperStep::Positional { patterns, capture } => {
                assert_eq!(patterns.len(), 1);
                assert!(patterns[0].is_wildcard());
                assert!(capture);
            }
            other => panic!("expected Positional step, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_flag_delimiter() {
        // (wrapper "terragrunt" (flag "--" :command+args))
        let config = parse(r#"(wrapper "terragrunt" (flag "--" :command+args))"#).unwrap();
        assert_eq!(config.wrappers[0].command, "terragrunt");
        match &config.wrappers[0].steps[0] {
            WrapperStep::Flag { name } => {
                assert_eq!(name, "--");
            }
            other => panic!("expected Flag step, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_validate_positional_then_flag() {
        // (wrapper "mise" (positional "exec") (flag "--" :command+args))
        let config = parse(
            r#"(wrapper "mise" (positional "exec") (flag "--" :command+args))"#,
        )
        .unwrap();
        assert_eq!(config.wrappers[0].command, "mise");
        assert_eq!(config.wrappers[0].steps.len(), 2);
        match &config.wrappers[0].steps[0] {
            WrapperStep::Positional { patterns, capture } => {
                assert_eq!(patterns.len(), 1);
                assert!(patterns[0].is_match("exec"));
                assert!(!capture);
            }
            other => panic!("expected Positional step, got {other:?}"),
        }
        match &config.wrappers[0].steps[1] {
            WrapperStep::Flag { name } => {
                assert_eq!(name, "--");
            }
            other => panic!("expected Flag step, got {other:?}"),
        }
    }

    #[test]
    fn wrapper_nix_style() {
        // (wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))
        let config = parse(
            r#"(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))"#,
        )
        .unwrap();
        assert_eq!(config.wrappers[0].command, "nix");
        match &config.wrappers[0].steps[0] {
            WrapperStep::Positional { patterns, capture } => {
                assert_eq!(patterns.len(), 1);
                assert!(patterns[0].is_match("shell"));
                assert!(patterns[0].is_match("develop"));
                assert!(!patterns[0].is_match("run"));
                assert!(!capture);
            }
            other => panic!("expected Positional step, got {other:?}"),
        }
        match &config.wrappers[0].steps[1] {
            WrapperStep::Flag { name } => {
                assert_eq!(name, "--command");
            }
            other => panic!("expected Flag step, got {other:?}"),
        }
    }

    #[test]
    fn blocked_paths_rejected() {
        let err = parse(r#"(blocked-paths "\\.secret/")"#).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no longer supported"), "got: {msg}");
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

            (wrapper "nohup" :command+args)
            (wrapper "mise" (positional "exec") (flag "--" :command+args))
        "#;
        let config = parse(input).unwrap();
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.wrappers.len(), 2);
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
    fn error_blocked_paths_rejected() {
        assert!(parse(r#"(blocked-paths "^[invalid")"#).is_err());
    }

    #[test]
    fn error_unknown_expected_in_check() {
        assert!(parse(
            r#"(rule (command "cat") (effect :allow) (check :maybe "cat foo"))"#
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
    fn error_unknown_expr_form() {
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
    fn error_check_too_few_parts() {
        assert!(parse(r#"(rule (command "cat") (effect :allow) (check :allow))"#).is_err());
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
    fn error_empty_expr_form() {
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
    fn error_wrapper_no_capture() {
        // Wrapper with a positional step but no capture keyword
        assert!(parse(r#"(wrapper "x" (positional "sub"))"#).is_err());
    }

    #[test]
    fn error_wrapper_duplicate_capture() {
        assert!(parse(r#"(wrapper "x" (positional "a" :command+args) (flag "--" :command+args))"#).is_err());
    }

    #[test]
    fn error_flag_wrong_arity() {
        assert!(parse(r#"(wrapper "x" (flag "--"))"#).is_err());
        assert!(parse(r#"(wrapper "x" (flag "--" :command+args "extra"))"#).is_err());
    }

    #[test]
    fn error_flag_bad_capture_keyword() {
        assert!(parse(r#"(wrapper "x" (flag "--" :bogus))"#).is_err());
    }

    #[test]
    fn error_unknown_wrapper_element() {
        assert!(parse(r#"(wrapper "x" (bogus "y"))"#).is_err());
    }

    #[test]
    fn error_unexpected_wrapper_atom() {
        // bare atom that isn't a capture keyword
        assert!(parse(r#"(wrapper "x" something-else)"#).is_err());
    }

    // ── Integration with engine ────────────────────────────────────────

    #[test]
    fn config_evaluates_correctly() {
        use may_i_engine as engine;

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
        use may_i_engine as engine;

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

        assert_eq!(
            engine::evaluate("git remote", &config).decision,
            Decision::Allow
        );
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
        "#;
        let config = parse(input).unwrap();
        assert_eq!(config.security.safe_env_vars.len(), 2);
        assert!(config.security.safe_env_vars.contains("HOME"));
        assert!(config.security.safe_env_vars.contains("EDITOR"));
        assert_eq!(config.rules.len(), 1);
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
                    (else
                     (effect :deny "Unknown tmux source-file")))))"#,
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert_eq!(arm.branches[0].effect.decision, Decision::Allow);
                assert_eq!(arm.branches[0].effect.reason.as_deref(), Some("Reloading config is safe"));
                assert!(arm.fallback.is_some()); // catch-all
                assert_eq!(arm.fallback.as_ref().unwrap().decision, Decision::Deny);
            }
            _ => panic!("expected Branching(Cond)"),
        }
    }

    #[test]
    fn cond_else_catchall() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (cond
                    ((positional "bar") (effect :allow))
                    (else
                     (effect :deny)))))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert!(arm.fallback.is_some()); // else is catch-all
            }
            _ => panic!("expected Branching(Cond)"),
        }
    }

    #[test]
    fn cond_with_checks() {
        let config = parse(
            r#"(rule (command "tmux")
                  (args (cond
                    ((positional "source-file" "~/.config/tmux/tmux.conf")
                     (effect :allow "Reloading config"))
                    (else
                     (effect :deny "Unknown tmux command"))))
                  (check :allow "tmux source-file ~/.config/tmux/tmux.conf"
                         :deny "tmux source-file /tmp/evil.conf"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].checks.len(), 2);
        assert_eq!(config.rules[0].checks[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].checks[1].expected, Decision::Deny);
    }

    #[test]
    fn check_multiple_pairs() {
        let config = parse(
            r#"(rule (command "ls")
                  (effect :allow)
                  (check :allow "ls" :allow "ls -la" :deny "ls /secret"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].checks.len(), 3);
        assert_eq!(config.rules[0].checks[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].checks[0].command, "ls");
        assert_eq!(config.rules[0].checks[1].expected, Decision::Allow);
        assert_eq!(config.rules[0].checks[1].command, "ls -la");
        assert_eq!(config.rules[0].checks[2].expected, Decision::Deny);
        assert_eq!(config.rules[0].checks[2].command, "ls /secret");
    }

    #[test]
    fn check_multiple_forms() {
        let config = parse(
            r#"(rule (command "ls")
                  (effect :allow)
                  (check :allow "ls -la")
                  (check :deny "ls /secret" :ask "ls /tmp"))"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].checks.len(), 3);
        assert_eq!(config.rules[0].checks[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].checks[1].expected, Decision::Deny);
        assert_eq!(config.rules[0].checks[2].expected, Decision::Ask);
    }

    #[test]
    fn check_odd_count_is_error() {
        assert!(parse(
            r#"(rule (command "ls") (effect :allow) (check :allow))"#
        )
        .is_err());
    }

    #[test]
    fn check_bad_decision_is_error() {
        assert!(parse(
            r#"(rule (command "ls") (effect :allow) (check :bogus "ls"))"#
        )
        .is_err());
    }

    #[test]
    fn cond_plus_effect_is_error() {
        assert!(parse(
            r#"(rule (command "x") (args (cond (else
             (effect :allow)))) (effect :deny))"#
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
        assert!(parse(r#"(rule (command "x") (args (cond (else
         ()))))"#).is_err());
    }

    #[test]
    fn error_cond_unknown_branch_element() {
        assert!(parse(
            r#"(rule (command "x") (args (cond (else
             (bogus "y")))))"#
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
            r#"(rule (command "x") (cond (else
             (effect :allow))))"#
        )
        .is_err());
    }

    #[test]
    fn cond_nested_in_and_with_effect() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (and (cond
                               ((positional "bar") (effect :allow))
                               (else
                                (effect :deny)))
                             (anywhere "--verbose")))
                  (effect :allow "verbose bar"))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Effect { matcher: Some(ArgMatcher::And(matchers)), effect } => {
                assert_eq!(effect.decision, Decision::Allow);
                assert_eq!(matchers.len(), 2);
                assert!(matches!(&matchers[0], ArgMatcher::Cond(_)));
                assert!(matches!(&matchers[1], ArgMatcher::Anywhere(_)));
            }
            _ => panic!("expected Effect with And matcher"),
        }
    }

    // ── if/when/unless matcher forms ─────────────────────────────────

    #[test]
    fn matcher_if_with_else() {
        let config = parse(
            r#"(rule (command "emacsclient")
                  (args (if (anywhere "--eval" "-e")
                            (effect :ask "Lisp evaluation is dangerous")
                            (effect :allow "Opening files"))))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert_eq!(arm.branches[0].effect.decision, Decision::Ask);
                assert!(arm.fallback.is_some()); // else
                assert_eq!(arm.fallback.as_ref().unwrap().decision, Decision::Allow);
            }
            _ => panic!("expected Branching(Cond) from if"),
        }
    }

    #[test]
    fn matcher_if_without_else() {
        let config = parse(
            r#"(rule (command "nix")
                  (args (if (positional "flake" "update")
                            (effect :ask "Flake update"))))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert_eq!(arm.branches[0].effect.decision, Decision::Ask);
            }
            _ => panic!("expected Branching(Cond) from if"),
        }
    }

    #[test]
    fn matcher_when() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (when (positional "bar")
                              (effect :allow))))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert_eq!(arm.branches[0].effect.decision, Decision::Allow);
            }
            _ => panic!("expected Branching(Cond) from when"),
        }
    }

    #[test]
    fn matcher_unless() {
        let config = parse(
            r#"(rule (command "foo")
                  (args (unless (anywhere "--force")
                                (effect :allow))))"#,
        )
        .unwrap();
        match &config.rules[0].body {
            RuleBody::Branching(ArgMatcher::Cond(arm)) => {
                assert_eq!(arm.branches.len(), 1);
                assert!(matches!(&arm.branches[0].matcher, ArgMatcher::Not(_)));
                assert_eq!(arm.branches[0].effect.decision, Decision::Allow);
            }
            _ => panic!("expected Branching(Cond) from unless"),
        }
    }

    #[test]
    fn error_matcher_if_too_many_args() {
        assert!(parse(
            r#"(rule (command "x") (args (if (positional "a") (effect :allow) (effect :deny) (effect :ask))))"#
        ).is_err());
    }

    #[test]
    fn error_matcher_when_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (when (positional "a"))))"#
        ).is_err());
    }

    #[test]
    fn error_matcher_unless_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (unless (positional "a"))))"#
        ).is_err());
    }

    #[test]
    fn or_matcher_evaluates_correctly() {
        use may_i_engine as engine;

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

    // ── Expr-level forms in pattern context ───────────────────────────

    #[test]
    fn expr_and_in_positional() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (and (regex "^a") (regex "b$"))))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(exprs) => {
                assert!(exprs[0].is_match("ab"));
                assert!(!exprs[0].is_match("ac"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_not_in_positional() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (not "bad")))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(exprs) => {
                assert!(exprs[0].is_match("good"));
                assert!(!exprs[0].is_match("bad"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_if_desugars_to_cond() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (if "a" (effect :allow) (effect :deny)))))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert!(matches!(pexprs[0].expr(), Expr::Cond(branches) if branches.len() == 2));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_if_without_else() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (if "a" (effect :allow)))))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert!(matches!(pexprs[0].expr(), Expr::Cond(branches) if branches.len() == 1));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_when_desugars_to_cond() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (when "a" (effect :deny)))))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert!(matches!(pexprs[0].expr(), Expr::Cond(branches) if branches.len() == 1));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_unless_desugars_to_not_cond() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (unless "bad" (effect :allow)))))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                match pexprs[0].expr() {
                    Expr::Cond(branches) => {
                        assert_eq!(branches.len(), 1);
                        assert!(matches!(&branches[0].test, Expr::Not(_)));
                    }
                    _ => panic!("expected Cond"),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn expr_cond_in_positional() {
        let config = parse(
            r#"(rule (command "x")
                   (args (positional (cond ("a" (effect :allow))
                                         (else (effect :deny))))))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                match pexprs[0].expr() {
                    Expr::Cond(branches) => {
                        assert_eq!(branches.len(), 2);
                        assert_eq!(branches[0].effect.decision, Decision::Allow);
                        assert_eq!(branches[1].effect.decision, Decision::Deny);
                    }
                    _ => panic!("expected Cond"),
                }
            }
            _ => panic!("expected Positional"),
        }
    }

    // ── Expr-level error cases ────────────────────────────────────────

    #[test]
    fn error_expr_not_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (not "a" "b"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_if_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (if "a"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_when_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (when "a"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_unless_wrong_arity() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (unless "a"))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_expr_cond_empty() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (cond))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_expr_cond_empty_branch() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (cond ()))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_expr_cond_empty_branch_element() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (cond ("a" ())))) (effect :allow))"#
        )
        .is_err());
    }

    #[test]
    fn error_expr_cond_unknown_branch_element() {
        assert!(parse(
            r#"(rule (command "x") (args (positional (cond ("a" (bogus :allow))))) (effect :allow))"#
        )
        .is_err());
    }

    // ── Expr::Cond as implicit rule effect ──────────────────────────

    #[test]
    fn expr_cond_in_positional_no_top_effect_parses() {
        let config = parse(
            r#"(rule (command "tmux")
                   (args (positional "source-file"
                                     (if (or "a" "b")
                                         (effect :allow "safe")
                                         (effect :deny "bad")))))"#,
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(&config.rules[0].body, RuleBody::Branching(_)));
    }

    #[test]
    fn expr_cond_in_positional_with_top_effect_is_error() {
        assert!(parse(
            r#"(rule (command "tmux")
                   (args (positional "source-file"
                                     (if (or "a" "b")
                                         (effect :allow "safe")
                                         (effect :deny "bad"))))
                   (effect :ask))"#
        )
        .is_err());
    }

    // ── PosExpr quantifier parsing ──────────────────────────────────

    #[test]
    fn positional_optional_quantifier() {
        let config = parse(
            r#"(rule (command "git")
                   (args (positional "stash" (? "pop")))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert_eq!(pexprs.len(), 2);
                assert!(matches!(&pexprs[0], PosExpr::One(_)));
                assert!(matches!(&pexprs[1], PosExpr::Optional(_)));
                assert!(pexprs[1].is_match("pop"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn positional_one_or_more_quantifier() {
        let config = parse(
            r#"(rule (command "cat")
                   (args (positional (+ (regex "^[^-]"))))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert_eq!(pexprs.len(), 1);
                assert!(matches!(&pexprs[0], PosExpr::OneOrMore(_)));
                assert!(pexprs[0].is_match("file.txt"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn positional_zero_or_more_quantifier() {
        let config = parse(
            r#"(rule (command "ls")
                   (args (positional (* *)))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert_eq!(pexprs.len(), 1);
                assert!(matches!(&pexprs[0], PosExpr::ZeroOrMore(_)));
                assert!(pexprs[0].is_wildcard());
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn exact_with_quantifiers() {
        let config = parse(
            r#"(rule (command "cmd")
                   (args (exact "sub" (? "opt") (+ *)))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::ExactPositional(pexprs) => {
                assert_eq!(pexprs.len(), 3);
                assert!(matches!(&pexprs[0], PosExpr::One(_)));
                assert!(matches!(&pexprs[1], PosExpr::Optional(_)));
                assert!(matches!(&pexprs[2], PosExpr::OneOrMore(_)));
            }
            _ => panic!("expected ExactPositional"),
        }
    }

    #[test]
    fn quantifier_with_complex_expr() {
        let config = parse(
            r#"(rule (command "cmd")
                   (args (positional (+ (or "a" "b" "c"))))
                   (effect :allow))"#,
        )
        .unwrap();
        match get_matcher(&config.rules[0]).unwrap() {
            ArgMatcher::Positional(pexprs) => {
                assert_eq!(pexprs.len(), 1);
                assert!(matches!(&pexprs[0], PosExpr::OneOrMore(_)));
                assert!(pexprs[0].is_match("a"));
                assert!(pexprs[0].is_match("b"));
                assert!(!pexprs[0].is_match("d"));
            }
            _ => panic!("expected Positional"),
        }
    }

    // ── Quantifier integration with engine ──────────────────────────

    #[test]
    fn quantifier_optional_evaluates() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "git")
                  (args (positional "stash" (? "pop")))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("git stash", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("git stash pop", &config).decision, Decision::Allow);
        // Non-exact positional allows extra args, so "drop" is ignored
        assert_eq!(engine::evaluate("git stash drop", &config).decision, Decision::Allow);
    }

    #[test]
    fn quantifier_one_or_more_evaluates() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "cat")
                  (args (positional (+ *)))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("cat file1", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("cat file1 file2 file3", &config).decision, Decision::Allow);
        // No positional args (just flags) — one-or-more requires at least one
        assert_eq!(engine::evaluate("cat", &config).decision, Decision::Ask);
    }

    #[test]
    fn quantifier_zero_or_more_evaluates() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "ls")
                  (args (positional (* *)))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("ls", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("ls dir1", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("ls dir1 dir2", &config).decision, Decision::Allow);
    }

    #[test]
    fn quantifier_exact_with_optional() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "git")
                  (args (exact "stash" (? "pop")))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("git stash", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("git stash pop", &config).decision, Decision::Allow);
        // Extra positional arg — exact rejects
        assert_eq!(engine::evaluate("git stash pop extra", &config).decision, Decision::Ask);
        // Mismatched optional — still only "stash" consumed, but "drop" is extra for exact
        assert_eq!(engine::evaluate("git stash drop", &config).decision, Decision::Ask);
    }

    #[test]
    fn quantifier_subcommand_plus_files() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "git")
                  (args (positional "add" (+ *)))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("git add file.txt", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("git add file1 file2", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("git add", &config).decision, Decision::Ask);
    }

    #[test]
    fn quantifier_mixed_fixed_and_variable() {
        use may_i_engine as engine;

        let config = parse(
            r#"
            (rule (command "kubectl")
                  (args (positional "get" (* (or "pods" "services" "deployments")) (? *)))
                  (effect :allow))
            "#,
        )
        .unwrap();

        assert_eq!(engine::evaluate("kubectl get pods", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("kubectl get pods services", &config).decision, Decision::Allow);
        assert_eq!(engine::evaluate("kubectl get pods mypod", &config).decision, Decision::Allow);
    }
}

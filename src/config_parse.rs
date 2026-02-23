// Configuration parsing — R10, R10a–R10f
// S-expression configuration for authorization rules, wrappers, and security.

use crate::errors::{ConfigError, RawError, Span};
use crate::sexpr::Sexpr;
use crate::types::{
    ArgMatcher, Check, CommandMatcher, CondBranch, Config, Decision, Effect, Expr, ExprBranch,
    PosExpr, Rule, SecurityConfig, Wrapper, WrapperKind,
};

/// Parse an s-expression config string into Config.
///
/// `filename` is used in diagnostic messages to identify the source file.
pub fn parse(input: &str, filename: &str) -> Result<Config, Box<ConfigError>> {
    parse_raw(input).map_err(|raw| Box::new(ConfigError::from_raw(raw, input, filename)))
}

fn parse_raw(input: &str) -> Result<Config, RawError> {
    let (forms, errors) = crate::sexpr::parse(input);
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
                    "blocked-paths is no longer supported; file access control is handled by syscall sandboxing",
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

fn parse_cond_branches(list: &[Sexpr]) -> Result<Vec<CondBranch>, RawError> {
    let branches = &list[1..];
    if branches.is_empty() {
        let span = list[0].span();
        return Err(RawError::new("cond must have at least one branch", span));
    }
    let mut result = Vec::new();
    for branch in branches {
        let items = branch.as_list().ok_or_else(|| {
            RawError::new("cond branch must be a list", branch.span())
        })?;
        if items.is_empty() {
            return Err(RawError::new("empty cond branch", branch.span()));
        }
        // First element: matcher or catch-all
        let matcher = match &items[0] {
            Sexpr::Atom(s, _) if s == "else" => None,
            other => Some(parse_matcher(other)?),
        };
        // Remaining elements: find (effect ...)
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
        result.push(CondBranch {
            matcher,
            effect: effect.ok_or_else(|| {
                RawError::new("cond branch must have an effect", branch.span())
            })?,
        });
    }
    Ok(result)
}

fn parse_matcher_if_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(RawError::new(
            "if must have 2 or 3 arguments: (if MATCHER EFFECT EFFECT?)",
            form_span,
        ));
    }
    let test = parse_matcher(&args[0])?;
    let then_list = args[1].as_list().ok_or_else(|| {
        RawError::new("if then-branch must be an effect list", args[1].span())
    })?;
    let then_effect = parse_effect(then_list)?;

    let mut branches = vec![CondBranch {
        matcher: Some(test),
        effect: then_effect,
    }];

    if args.len() == 3 {
        let else_list = args[2].as_list().ok_or_else(|| {
            RawError::new("if else-branch must be an effect list", args[2].span())
        })?;
        let else_effect = parse_effect(else_list)?;
        branches.push(CondBranch {
            matcher: None,
            effect: else_effect,
        });
    }

    Ok(ArgMatcher::Cond(branches))
}

fn parse_matcher_when_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "when must have exactly 2 arguments: (when MATCHER EFFECT)",
            form_span,
        ));
    }
    let test = parse_matcher(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("when effect must be an effect list", args[1].span())
    })?;
    let effect = parse_effect(effect_list)?;
    Ok(ArgMatcher::Cond(vec![CondBranch {
        matcher: Some(test),
        effect,
    }]))
}

fn parse_matcher_unless_form(args: &[Sexpr], form_span: Span) -> Result<ArgMatcher, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "unless must have exactly 2 arguments: (unless MATCHER EFFECT)",
            form_span,
        ));
    }
    let test = parse_matcher(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("unless effect must be an effect list", args[1].span())
    })?;
    let effect = parse_effect(effect_list)?;
    Ok(ArgMatcher::Cond(vec![CondBranch {
        matcher: Some(ArgMatcher::Not(Box::new(test))),
        effect,
    }]))
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

    // Validate: embedded effects (top-level cond or Expr::Cond) are mutually exclusive with effect
    let has_embedded_effect = matcher.as_ref().is_some_and(|m| {
        matches!(m, ArgMatcher::Cond(_)) || m.has_effect()
    });
    if has_embedded_effect && effect.is_some() {
        return Err(RawError::new(
            "cond and effect are mutually exclusive in a rule",
            rule_span,
        ));
    }
    if !has_embedded_effect && effect.is_none() {
        return Err(RawError::new(
            "rule must have an effect (or a top-level cond matcher)",
            rule_span,
        ));
    }

    Ok(Rule {
        command: command.ok_or_else(|| {
            RawError::new("rule must have a command", rule_span)
        })?,
        matcher,
        effect,
        checks,
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

fn parse_pos_expr(sexpr: &Sexpr) -> Result<PosExpr, RawError> {
    if let Sexpr::List(list, _) = sexpr
        && list.len() == 2
        && let Some(tag) = list[0].as_atom()
    {
        match tag {
            "?" => return Ok(PosExpr::Optional(parse_expr(&list[1])?)),
            "+" => return Ok(PosExpr::OneOrMore(parse_expr(&list[1])?)),
            "*" => return Ok(PosExpr::ZeroOrMore(parse_expr(&list[1])?)),
            _ => {}
        }
    }
    Ok(PosExpr::One(parse_expr(sexpr)?))
}

fn parse_expr(sexpr: &Sexpr) -> Result<Expr, RawError> {
    match sexpr {
        Sexpr::Atom(s, _) if s == "*" => Ok(Expr::Wildcard),
        Sexpr::Atom(s, _) => Ok(Expr::Literal(s.clone())),
        Sexpr::List(list, span) => {
            if list.is_empty() {
                return Err(RawError::new("empty expression form", *span));
            }
            let tag = list[0].as_atom().ok_or_else(|| {
                RawError::new("expression form tag must be an atom", list[0].span())
            })?;
            match tag {
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
                            format!("invalid regex '{pat}': {e}"),
                            list[1].span(),
                        )
                    })?;
                    Ok(Expr::Regex(re))
                }
                "or" => {
                    let exprs: Result<Vec<Expr>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::Or(exprs?))
                }
                "and" => {
                    let exprs: Result<Vec<Expr>, _> =
                        list[1..].iter().map(parse_expr).collect();
                    Ok(Expr::And(exprs?))
                }
                "not" => {
                    if list.len() != 2 {
                        return Err(RawError::new(
                            "not must have exactly one expression",
                            *span,
                        ));
                    }
                    Ok(Expr::Not(Box::new(parse_expr(&list[1])?)))
                }
                "cond" => {
                    let branches = parse_expr_cond_branches(&list[1..])?;
                    Ok(Expr::Cond(branches))
                }
                "if" => parse_if_form(&list[1..], *span),
                "when" => parse_when_form(&list[1..], *span),
                "unless" => parse_unless_form(&list[1..], *span),
                other => Err(RawError::new(
                    format!("unknown expression form: {other}"),
                    list[0].span(),
                )
                .with_label("not a recognised expression form")
                .with_help("valid expression forms: regex, or, and, not, cond, if, when, unless")),
            }
        }
    }
}

fn parse_expr_cond_branches(branches: &[Sexpr]) -> Result<Vec<ExprBranch>, RawError> {
    if branches.is_empty() {
        return Err(RawError::new(
            "cond must have at least one branch",
            Span::new(0, 0),
        ));
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
            Sexpr::Atom(s, _) if s == "else" => Expr::Wildcard,
            other => parse_expr(other)?,
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
        result.push(ExprBranch {
            test,
            effect: effect.ok_or_else(|| {
                RawError::new("cond branch must have an effect", branch.span())
            })?,
        });
    }
    Ok(result)
}

fn parse_if_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(RawError::new(
            "if must have 2 or 3 arguments: (if EXPR EFFECT EFFECT?)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let then_list = args[1].as_list().ok_or_else(|| {
        RawError::new("if then-branch must be an effect list", args[1].span())
    })?;
    let then_effect = parse_effect(then_list)?;

    let mut branches = vec![ExprBranch { test, effect: then_effect }];

    if args.len() == 3 {
        let else_list = args[2].as_list().ok_or_else(|| {
            RawError::new("if else-branch must be an effect list", args[2].span())
        })?;
        let else_effect = parse_effect(else_list)?;
        branches.push(ExprBranch {
            test: Expr::Wildcard,
            effect: else_effect,
        });
    }

    Ok(Expr::Cond(branches))
}

fn parse_when_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "when must have exactly 2 arguments: (when EXPR EFFECT)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("when effect must be an effect list", args[1].span())
    })?;
    let effect = parse_effect(effect_list)?;
    Ok(Expr::Cond(vec![ExprBranch { test, effect }]))
}

fn parse_unless_form(args: &[Sexpr], form_span: Span) -> Result<Expr, RawError> {
    if args.len() != 2 {
        return Err(RawError::new(
            "unless must have exactly 2 arguments: (unless EXPR EFFECT)",
            form_span,
        ));
    }
    let test = parse_expr(&args[0])?;
    let effect_list = args[1].as_list().ok_or_else(|| {
        RawError::new("unless effect must be an effect list", args[1].span())
    })?;
    let effect = parse_effect(effect_list)?;
    Ok(Expr::Cond(vec![ExprBranch {
        test: Expr::Not(Box::new(test)),
        effect,
    }]))
}

fn parse_wrapper(parts: &[Sexpr], wrapper_span: Span) -> Result<Wrapper, RawError> {
    // (wrapper "nohup" after-flags)
    // (wrapper "mise" (positional "exec") (after "--"))
    if parts.is_empty() {
        return Err(RawError::new(
            "wrapper must have a command name",
            wrapper_span,
        ));
    }

    let command = parts[0]
        .as_atom()
        .ok_or_else(|| {
            RawError::new("wrapper command must be a string", parts[0].span())
        })?
        .to_string();

    let mut positional_args = Vec::new();
    let mut kind = None;

    for part in &parts[1..] {
        match part {
            Sexpr::Atom(s, _) if s == "after-flags" => {
                kind = Some(WrapperKind::AfterFlags);
            }
            Sexpr::List(list, span) if !list.is_empty() => {
                let tag = list[0].as_atom().ok_or_else(|| {
                    RawError::new("wrapper element tag must be an atom", list[0].span())
                })?;
                match tag {
                    "positional" => {
                        for item in &list[1..] {
                            positional_args.push(parse_expr(item)?);
                        }
                    }
                    "after" => {
                        if list.len() != 2 {
                            return Err(RawError::new(
                                "after must have exactly one delimiter",
                                *span,
                            ));
                        }
                        let delim = list[1]
                            .as_atom()
                            .ok_or_else(|| {
                                RawError::new(
                                    "after delimiter must be a string",
                                    list[1].span(),
                                )
                            })?
                            .to_string();
                        kind = Some(WrapperKind::AfterDelimiter(delim));
                    }
                    other => {
                        return Err(RawError::new(
                            format!("unknown wrapper element: {other}"),
                            list[0].span(),
                        )
                        .with_label("not a recognised wrapper element")
                        .with_help("valid wrapper elements: positional, after"));
                    }
                }
            }
            _ => {
                return Err(RawError::new(
                    "unexpected wrapper element",
                    part.span(),
                ));
            }
        }
    }

    Ok(Wrapper {
        command,
        positional_args,
        kind: kind.ok_or_else(|| {
            RawError::new(
                "wrapper must specify after-flags or (after ...)",
                wrapper_span,
            )
        })?,
    })
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
        assert_eq!(rule.effect.as_ref().unwrap().decision, Decision::Allow);
        assert!(rule.matcher.is_none());
        assert!(rule.effect.as_ref().unwrap().reason.is_none());
    }

    #[test]
    fn deny_with_reason() {
        let config = parse(r#"(rule (command "rm") (effect :deny "dangerous"))"#).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.effect.as_ref().unwrap().decision, Decision::Deny);
        assert_eq!(rule.effect.as_ref().unwrap().reason.as_deref(), Some("dangerous"));
    }

    #[test]
    fn ask_with_reason() {
        let config = parse(r#"(rule (command "curl") (effect :ask "network op"))"#).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.effect.as_ref().unwrap().decision, Decision::Ask);
        assert_eq!(rule.effect.as_ref().unwrap().reason.as_deref(), Some("network op"));
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

            (wrapper "nohup" after-flags)
            (wrapper "mise" (positional "exec") (after "--"))
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 2);
                assert!(branches[0].matcher.is_some());
                assert_eq!(branches[0].effect.decision, Decision::Allow);
                assert_eq!(branches[0].effect.reason.as_deref(), Some("Reloading config is safe"));
                assert!(branches[1].matcher.is_none()); // catch-all
                assert_eq!(branches[1].effect.decision, Decision::Deny);
            }
            _ => panic!("expected Cond"),
        }
        assert!(config.rules[0].effect.is_none());
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 2);
                assert!(branches[1].matcher.is_none()); // else is catch-all
            }
            _ => panic!("expected Cond"),
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
        assert_eq!(config.rules[0].effect.as_ref().unwrap().decision, Decision::Allow);
        match &config.rules[0].matcher {
            Some(ArgMatcher::And(matchers)) => {
                assert_eq!(matchers.len(), 2);
                assert!(matches!(&matchers[0], ArgMatcher::Cond(_)));
                assert!(matches!(&matchers[1], ArgMatcher::Anywhere(_)));
            }
            _ => panic!("expected And"),
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 2);
                assert!(branches[0].matcher.is_some());
                assert_eq!(branches[0].effect.decision, Decision::Ask);
                assert!(branches[1].matcher.is_none()); // else
                assert_eq!(branches[1].effect.decision, Decision::Allow);
            }
            _ => panic!("expected Cond from if"),
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 1);
                assert!(branches[0].matcher.is_some());
                assert_eq!(branches[0].effect.decision, Decision::Ask);
            }
            _ => panic!("expected Cond from if"),
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 1);
                assert!(branches[0].matcher.is_some());
                assert_eq!(branches[0].effect.decision, Decision::Allow);
            }
            _ => panic!("expected Cond from when"),
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
        match &config.rules[0].matcher {
            Some(ArgMatcher::Cond(branches)) => {
                assert_eq!(branches.len(), 1);
                assert!(matches!(&branches[0].matcher, Some(ArgMatcher::Not(_))));
                assert_eq!(branches[0].effect.decision, Decision::Allow);
            }
            _ => panic!("expected Cond from unless"),
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
        assert!(config.rules[0].effect.is_none());
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
        use crate::engine;

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
        use crate::engine;

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
        use crate::engine;

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
        use crate::engine;

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
        use crate::engine;

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
        use crate::engine;

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

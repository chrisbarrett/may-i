// Config parser for the unified DSL.

use may_i_core::Span;
use may_i_core::ast::{
    AuditConfig, AuditThreshold, Check, Config, Effect, EnvCapability, Predicate, Provenance,
    RedirectCapability, SecurityConfig, Spanned,
};
use may_i_core::pattern::ArgPattern;
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
                parse_safe_env_vars(&list[1..], &mut config.security.safe_env_vars, form.span())?;
            }
            "env" => {
                let (names, decision) = parse_env_form(&list[1..], form.span())?;
                for name in names {
                    ingest_env_capability(&mut config.security, name, decision.clone(), false);
                }
            }
            "redirect" => {
                let cap = parse_redirect_form(&list[1..], form.span())?;
                ingest_redirect_capability(&mut config.security, cap, false);
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
                    "valid top-level forms: rule, define, safe-env-vars, env, redirect, check, audit, define-arg-style, parser",
                ));
            }
        }
    }

    validate_named_capabilities(&config)?;
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
                if provenance.is_loaded() {
                    parse_safe_env_vars(
                        &list[1..],
                        &mut config.security.loaded_safe_env_vars,
                        form.span(),
                    )?;
                    config.security.has_loaded_env_vars = true;
                } else {
                    parse_safe_env_vars(
                        &list[1..],
                        &mut config.security.safe_env_vars,
                        form.span(),
                    )?;
                }
            }
            "env" => {
                let (names, decision) = parse_env_form(&list[1..], form.span())?;
                for name in names {
                    ingest_env_capability(
                        &mut config.security,
                        name,
                        decision.clone(),
                        provenance.is_loaded(),
                    );
                }
            }
            "redirect" => {
                let cap = parse_redirect_form(&list[1..], form.span())?;
                ingest_redirect_capability(&mut config.security, cap, provenance.is_loaded());
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
                    "valid top-level forms: rule, define, safe-env-vars, env, redirect, check, audit, define-arg-style, parser",
                ));
            }
        }
    }

    validate_named_capabilities(&config)?;
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

/// Parse safe-env-vars form: (safe-env-vars "VAR1" "VAR2" ...).
/// Entries land in `target` — the primary set, or the trust-scoped
/// loaded set when the form comes from a loaded file.
fn parse_safe_env_vars(
    args: &[Sexpr],
    target: &mut std::collections::HashSet<String>,
    _span: Span,
) -> Result<(), RawError> {
    for item in args {
        let s = item
            .as_atom_or_str()
            .ok_or_else(|| RawError::new("safe-env-vars entry must be a string", item.span()))?;
        target.insert(s.to_string());
    }
    Ok(())
}

/// Parse an `(env SUBJECT DECISION)` capability form into one or more
/// variable names and the shared fact-conditioned decision expression.
/// SUBJECT is either a single name (`(env "FOO" …)`) or an `(or NAME…)`
/// name-set (`(env (or "A" "B") …)`) that applies the same decision to
/// every listed name. The decision is parsed with the rule-body parser and
/// validated to contain no argv/binding constructs (a capability is
/// command-agnostic).
fn parse_env_form(args: &[Sexpr], span: Span) -> Result<(Vec<String>, Spanned<Effect>), RawError> {
    if args.len() != 2 {
        return Err(
            RawError::new("(env SUBJECT DECISION) takes a name and a decision", span).with_help(
                "e.g. (env \"LD_PRELOAD\" (deny)), (env \"GIT_PAGER\" (allow)), \
                 or (env (or \"A\" \"B\") (deny))",
            ),
        );
    }
    let names = parse_env_subject(&args[0])?;
    let decision = crate::effect::parse_effect(&args[1])?;
    validate_capability_effect(&decision.value, decision.span)?;
    Ok((names, decision))
}

/// Parse the SUBJECT of an `(env …)` form: a single name string, or an
/// `(or NAME…)` set of names.
fn parse_env_subject(subject: &Sexpr) -> Result<Vec<String>, RawError> {
    if let Some(name) = subject.as_atom_or_str() {
        return Ok(vec![name.to_string()]);
    }
    let list = subject.as_list().ok_or_else(|| {
        RawError::new(
            "(env …) subject must be a variable name or (or NAME…)",
            subject.span(),
        )
    })?;
    let head = list.first().and_then(Sexpr::as_atom);
    if head != Some("or") || list.len() < 2 {
        return Err(RawError::new(
            "(env …) subject must be a variable name or (or NAME…)",
            subject.span(),
        )
        .with_help("e.g. (env \"FOO\" …) or (env (or \"A\" \"B\") …)"));
    }
    list[1..]
        .iter()
        .map(|item| {
            item.as_atom_or_str()
                .map(str::to_string)
                .ok_or_else(|| RawError::new("(env (or …)) entries must be strings", item.span()))
        })
        .collect()
}

/// Parse a `(redirect PATTERN? DECISION)` capability form. Arity 1 is
/// `(redirect DECISION)` (matches any write target); arity 2 is
/// `(redirect PATTERN DECISION)`.
fn parse_redirect_form(args: &[Sexpr], span: Span) -> Result<RedirectCapability, RawError> {
    let (pattern, decision_sexpr) = match args {
        [decision] => (None, decision),
        [pat, decision] => (Some(crate::pattern::parse_expr_for_capture(pat)?), decision),
        _ => {
            return Err(RawError::new(
                "(redirect PATTERN? DECISION) takes an optional target pattern and a decision",
                span,
            )
            .with_help("e.g. (redirect (regex \"^/tmp/\") (allow)) or (redirect (allow))"));
        }
    };
    let decision = crate::effect::parse_effect(decision_sexpr)?;
    validate_capability_effect(&decision.value, decision.span)?;
    Ok(RedirectCapability { pattern, decision })
}

/// Route a parsed `(env …)` capability into the security config. An
/// unconditional `(env NAME (allow))` lowers to the safe-env-vars
/// allowlist — exactly the historic `(safe-env-vars NAME)` entry — so the
/// two spellings share one representation and trust scope. Everything else
/// (ask/deny/conditional) becomes an `EnvCapability`.
fn ingest_env_capability(
    security: &mut SecurityConfig,
    name: String,
    decision: Spanned<Effect>,
    loaded: bool,
) {
    if matches!(
        decision.value,
        Effect::Terminal {
            decision: Decision::Allow,
            ..
        }
    ) {
        if loaded {
            security.loaded_safe_env_vars.insert(name);
            security.has_loaded_env_vars = true;
        } else {
            security.safe_env_vars.insert(name);
        }
    } else if loaded {
        security
            .loaded_env_caps
            .push(EnvCapability { name, decision });
        security.has_loaded_env_caps = true;
    } else {
        security.env_caps.push(EnvCapability { name, decision });
    }
}

/// Route a parsed `(redirect …)` capability into the security config.
fn ingest_redirect_capability(
    security: &mut SecurityConfig,
    cap: RedirectCapability,
    loaded: bool,
) {
    if loaded {
        security.loaded_redirect_caps.push(cap);
        security.has_loaded_redirect_caps = true;
    } else {
        security.redirect_caps.push(cap);
    }
}

/// A short label for an argv/binding form that is forbidden in a
/// capability decision, used in the load-time diagnostic.
fn arg_pattern_label(pat: &ArgPattern) -> &'static str {
    use may_i_core::pattern::MatchMode;
    match pat {
        ArgPattern::Ordered {
            mode: MatchMode::Positional,
            ..
        } => "(positional …)",
        ArgPattern::Ordered {
            mode: MatchMode::Exact,
            ..
        } => "(exact …)",
        ArgPattern::Anywhere(_) => "(anywhere …)",
        ArgPattern::Forbidden(_) => "(forbidden …)",
        ArgPattern::Flag { .. } => "(flag …)",
        ArgPattern::Parameter { .. } => "(parameter …)",
        ArgPattern::Tail => "(tail …)",
    }
}

/// Build the load-time error for a forbidden capability-decision form.
fn capability_form_error(form: &str, span: Span) -> RawError {
    RawError::new(
        format!("{form} is not permitted in a capability decision"),
        span,
    )
    .with_help(
        "a capability is command-agnostic (no argv referent): its decision may use only \
         the terminals (allow|ask|deny), the combinators (and|or|not), the conditionals \
         (if|when|unless|cond), and (fact? …)",
    )
}

/// Reject argv-analysis and parser-binding constructs in a capability
/// decision expression (design D6). Walks the fact-conditioned subset and
/// errors on the first forbidden form, naming it.
fn validate_capability_effect(effect: &Effect, span: Span) -> Result<(), RawError> {
    match effect {
        Effect::Terminal { .. } => Ok(()),
        Effect::CommandPattern(_) => Err(capability_form_error("a bare command pattern", span)),
        Effect::ArgPattern(pat) => Err(capability_form_error(arg_pattern_label(pat), span)),
        Effect::Authorise { .. } => Err(capability_form_error("(authorise …)", span)),
        Effect::And { effects } | Effect::Or { effects } => effects
            .iter()
            .try_for_each(|e| validate_capability_effect(&e.value, e.span)),
        Effect::Not { effect } => validate_capability_effect(&effect.value, effect.span),
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            validate_capability_predicate(&predicate.value, predicate.span)?;
            validate_capability_effect(&effect.value, effect.span)
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            validate_capability_predicate(&predicate.value, predicate.span)?;
            validate_capability_effect(&then_effect.value, then_effect.span)?;
            validate_capability_effect(&else_effect.value, else_effect.span)
        }
        Effect::Cond { branches, fallback } => {
            for (predicate, body) in branches {
                validate_capability_predicate(&predicate.value, predicate.span)?;
                validate_capability_effect(&body.value, body.span)?;
            }
            if let Some(fb) = fallback {
                validate_capability_effect(&fb.value, fb.span)?;
            }
            Ok(())
        }
    }
}

/// Reject argv/binding predicates in a capability decision. `(fact? …)`,
/// `(and|or|not …)` of facts, and `(define …)`d names are permitted; named
/// references are resolved and re-checked once the full config is known
/// (see [`validate_named_capabilities`]).
fn validate_capability_predicate(pred: &Predicate, span: Span) -> Result<(), RawError> {
    match pred {
        Predicate::Fact(_) | Predicate::Named(_) => Ok(()),
        Predicate::And(preds) | Predicate::Or(preds) => preds
            .iter()
            .try_for_each(|p| validate_capability_predicate(p, span)),
        Predicate::Not(inner) => validate_capability_predicate(inner, span),
        Predicate::Arg(pat) => Err(capability_form_error(arg_pattern_label(pat), span)),
        Predicate::Bound { .. } => Err(capability_form_error("(bound? …)", span)),
        Predicate::Matches { .. } => Err(capability_form_error("(matches? …)", span)),
        Predicate::Every { .. } => Err(capability_form_error("(every? …)", span)),
        Predicate::Some { .. } => Err(capability_form_error("(some? …)", span)),
        // `Predicate` is `#[non_exhaustive]`: reject any future variant rather
        // than silently admitting it into a capability decision (fail closed).
        _ => Err(capability_form_error("an unsupported predicate", span)),
    }
}

/// After all forms are parsed, re-check every capability decision's named
/// predicate references against the collected `(define …)`s: a capability
/// must not reach an argv/binding construct even transitively through a
/// `(define …)`.
fn validate_named_capabilities(config: &Config) -> Result<(), RawError> {
    let defines: std::collections::HashMap<&str, &Predicate> = config
        .defines
        .iter()
        .map(|d| (d.name.as_str(), &d.predicate.value))
        .collect();
    let caps = config
        .security
        .env_caps
        .iter()
        .map(|c| &c.decision)
        .chain(config.security.loaded_env_caps.iter().map(|c| &c.decision))
        .chain(config.security.redirect_caps.iter().map(|c| &c.decision))
        .chain(
            config
                .security
                .loaded_redirect_caps
                .iter()
                .map(|c| &c.decision),
        );
    for decision in caps {
        check_effect_named_defines(&decision.value, decision.span, &defines)?;
    }
    Ok(())
}

fn check_effect_named_defines(
    effect: &Effect,
    _span: Span,
    defines: &std::collections::HashMap<&str, &Predicate>,
) -> Result<(), RawError> {
    match effect {
        Effect::And { effects } | Effect::Or { effects } => effects
            .iter()
            .try_for_each(|e| check_effect_named_defines(&e.value, e.span, defines)),
        Effect::Not { effect } => check_effect_named_defines(&effect.value, effect.span, defines),
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            check_predicate_named_defines(
                &predicate.value,
                predicate.span,
                defines,
                &mut Vec::new(),
            )?;
            check_effect_named_defines(&effect.value, effect.span, defines)
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            check_predicate_named_defines(
                &predicate.value,
                predicate.span,
                defines,
                &mut Vec::new(),
            )?;
            check_effect_named_defines(&then_effect.value, then_effect.span, defines)?;
            check_effect_named_defines(&else_effect.value, else_effect.span, defines)
        }
        Effect::Cond { branches, fallback } => {
            for (predicate, body) in branches {
                check_predicate_named_defines(
                    &predicate.value,
                    predicate.span,
                    defines,
                    &mut Vec::new(),
                )?;
                check_effect_named_defines(&body.value, body.span, defines)?;
            }
            if let Some(fb) = fallback {
                check_effect_named_defines(&fb.value, fb.span, defines)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_predicate_named_defines<'a>(
    pred: &'a Predicate,
    span: Span,
    defines: &std::collections::HashMap<&'a str, &'a Predicate>,
    seen: &mut Vec<&'a str>,
) -> Result<(), RawError> {
    match pred {
        Predicate::Named(name) => {
            if seen.contains(&name.as_str()) {
                return Ok(()); // cycle guard
            }
            if let Some(resolved) = defines.get(name.as_str()) {
                seen.push(name.as_str());
                check_predicate_named_defines(resolved, span, defines, seen)?;
                seen.pop();
            }
            Ok(())
        }
        Predicate::And(preds) | Predicate::Or(preds) => preds
            .iter()
            .try_for_each(|p| check_predicate_named_defines(p, span, defines, seen)),
        Predicate::Not(inner) => check_predicate_named_defines(inner, span, defines, seen),
        other => validate_capability_predicate(other, span),
    }
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

    // ── capability forms: (env …) / (redirect …) ──────────────────

    #[test]
    fn parse_env_allow_lowers_to_safe_env_vars() {
        // (env NAME (allow)) is exactly (safe-env-vars NAME): one allowlist
        // entry, no EnvCapability.
        let config = parse_config(r#"(env "GIT_PAGER" (allow))"#).unwrap();
        assert!(config.security.safe_env_vars.contains("GIT_PAGER"));
        assert!(config.security.env_caps.is_empty());
    }

    #[test]
    fn safe_env_vars_and_taint_candidates_are_disjoint() {
        // Load-bearing invariant: `env_capability_names` (the secret-read
        // taint candidates) excludes `safe_env_vars` because an unconditional
        // env-write allow is read-inert. A mix of allow + ask + deny on
        // distinct names must keep the two sets disjoint, so a write-allow can
        // never be silently treated as a read taint candidate (or vice versa).
        let config = parse_config(
            r#"(env "GIT_PAGER" (allow)) (env "AWS_TOKEN" (deny)) (env "NPM_TOKEN" (ask))"#,
        )
        .unwrap();
        let candidates = config.security.env_capability_names();
        assert!(config.security.safe_env_vars.contains("GIT_PAGER"));
        assert!(candidates.contains("AWS_TOKEN") && candidates.contains("NPM_TOKEN"));
        assert!(
            config
                .security
                .safe_env_vars
                .iter()
                .all(|name| !candidates.contains(name)),
            "safe_env_vars and taint candidates must be disjoint"
        );
    }

    #[test]
    fn parse_env_deny_becomes_capability() {
        let config = parse_config(r#"(env "LD_PRELOAD" (deny))"#).unwrap();
        assert!(!config.security.safe_env_vars.contains("LD_PRELOAD"));
        assert_eq!(config.security.env_caps.len(), 1);
        assert_eq!(config.security.env_caps[0].name, "LD_PRELOAD");
        assert!(matches!(
            config.security.env_caps[0].decision.value,
            Effect::Terminal {
                decision: Decision::Deny,
                ..
            }
        ));
    }

    #[test]
    fn parse_env_ask_becomes_capability() {
        let config = parse_config(r#"(env "AWS_TOKEN" (ask "secret"))"#).unwrap();
        assert_eq!(config.security.env_caps.len(), 1);
        assert!(matches!(
            config.security.env_caps[0].decision.value,
            Effect::Terminal {
                decision: Decision::Ask,
                ..
            }
        ));
    }

    #[test]
    fn parse_env_fact_conditioned_decision() {
        let config = parse_config(r#"(env "AWS_TOKEN" (if (fact? :ci) (deny) (ask)))"#).unwrap();
        assert_eq!(config.security.env_caps.len(), 1);
        assert!(matches!(
            config.security.env_caps[0].decision.value,
            Effect::If { .. }
        ));
    }

    #[test]
    fn parse_env_or_name_set_applies_decision_to_each() {
        let config = parse_config(r#"(env (or "AWS_TOKEN" "GH_TOKEN") (deny))"#).unwrap();
        assert_eq!(config.security.env_caps.len(), 2);
        let names: Vec<&str> = config
            .security
            .env_caps
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(names.contains(&"AWS_TOKEN"));
        assert!(names.contains(&"GH_TOKEN"));
    }

    #[test]
    fn parse_env_or_name_set_allow_lowers_each_to_allowlist() {
        let config = parse_config(r#"(env (or "HOME" "USER") (allow))"#).unwrap();
        assert!(config.security.safe_env_vars.contains("HOME"));
        assert!(config.security.safe_env_vars.contains("USER"));
        assert!(config.security.env_caps.is_empty());
    }

    #[test]
    fn parse_env_bad_subject_is_error() {
        let err = parse_config(r#"(env (and "A" "B") (deny))"#).expect_err("error");
        assert!(format!("{err}").contains("subject"));
    }

    #[test]
    fn parse_env_missing_decision_is_error() {
        let err = parse_config(r#"(env "X")"#).expect_err("expected error");
        assert!(format!("{err}").contains("(env SUBJECT DECISION)"));
    }

    #[test]
    fn parse_redirect_with_pattern_and_decision() {
        let config = parse_config(r#"(redirect (regex "^/tmp/") (allow))"#).unwrap();
        assert_eq!(config.security.redirect_caps.len(), 1);
        assert!(config.security.redirect_caps[0].pattern.is_some());
    }

    #[test]
    fn parse_redirect_any_target() {
        // arity-1 (redirect DECISION) matches any write target.
        let config = parse_config(r#"(redirect (allow))"#).unwrap();
        assert_eq!(config.security.redirect_caps.len(), 1);
        assert!(config.security.redirect_caps[0].pattern.is_none());
    }

    #[test]
    fn parse_redirect_literal_pattern() {
        let config = parse_config(r#"(redirect "out.txt" (deny))"#).unwrap();
        assert_eq!(config.security.redirect_caps.len(), 1);
        assert!(config.security.redirect_caps[0].pattern.is_some());
    }

    #[test]
    fn parse_redirect_too_many_args_is_error() {
        let err = parse_config(r#"(redirect (regex "a") (regex "b") (allow))"#).expect_err("error");
        assert!(format!("{err}").contains("(redirect"));
    }

    #[test]
    fn old_safe_env_vars_config_still_loads() {
        let config = parse_config(r#"(safe-env-vars "HOME" "USER")"#).unwrap();
        assert_eq!(config.security.safe_env_vars.len(), 2);
        assert!(config.security.env_caps.is_empty());
    }

    #[test]
    fn capability_decision_rejects_argv_construct() {
        // Argv analysis has no command referent in a capability.
        let err = parse_config(r#"(env "X" (when (positional "y") (deny)))"#)
            .expect_err("expected error");
        let msg = format!("{err}");
        assert!(msg.contains("(positional"), "got: {msg}");
        assert!(msg.contains("not permitted"), "got: {msg}");
    }

    #[test]
    fn capability_decision_rejects_authorise() {
        let err = parse_config(r#"(env "X" (authorise #cmd))"#).expect_err("error");
        assert!(format!("{err}").contains("not permitted"));
    }

    #[test]
    fn capability_decision_rejects_bare_command_pattern() {
        // A bare command pattern in decision position has no referent.
        let err = parse_config(r#"(env "X" (or "git" "gh"))"#).expect_err("error");
        assert!(format!("{err}").contains("not permitted"));
    }

    #[test]
    fn capability_decision_rejects_flag_predicate() {
        let err = parse_config(r#"(env "X" (when (flag "v") (deny)))"#).expect_err("error");
        assert!(format!("{err}").contains("(flag"));
    }

    #[test]
    fn redirect_decision_rejects_argv_construct() {
        let err = parse_config(r#"(redirect (regex "^/tmp/") (when (positional "y") (deny)))"#)
            .expect_err("error");
        assert!(format!("{err}").contains("(positional"));
    }

    #[test]
    fn capability_decision_rejects_argv_via_named_define_in_cond() {
        // Resolution recurses through (cond …) branches and (and …) of names.
        let err = parse_config(
            r#"
            (define argvish (positional "x"))
            (env "X" (cond ((and argvish (fact? :ci)) (deny)) (else (ask))))
        "#,
        )
        .expect_err("error");
        assert!(format!("{err}").contains("not permitted"));
    }

    #[test]
    fn capability_decision_rejects_argv_via_named_define() {
        // A (define …) that resolves to an argv predicate is rejected too.
        let err = parse_config(
            r#"
            (define has-push (positional "push"))
            (env "X" (when has-push (deny)))
        "#,
        )
        .expect_err("expected error");
        assert!(format!("{err}").contains("not permitted"));
    }

    #[test]
    fn capability_decision_allows_facts_and_conditionals() {
        // Facts, named fact defines, and conditionals are all permitted.
        let config = parse_config(
            r#"
            (define on-ci (fact? :ci))
            (env "X" (when on-ci (deny)))
            (redirect (regex "^/tmp/") (if (fact? :ci) (deny) (allow)))
        "#,
        )
        .unwrap();
        assert_eq!(config.security.env_caps.len(), 1);
        assert_eq!(config.security.redirect_caps.len(), 1);
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

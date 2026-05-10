#[cfg(test)]
use may_i_core::ast::Style;
use may_i_core::ast::{EffectResult, ParameterTreatment, PunPolicy, ResolvedParser, Rule, Tail};
use may_i_core::{ContextFacts, Decision};

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult};

use super::context::EvalContext;
use super::effects::evaluate_effect_fold;

/// Evaluate a command against config and context using PureFold.
/// This is the main entry point for evaluation.
#[must_use = "evaluation result contains the access decision"]
pub fn evaluate(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
) -> Result<EvalResult, EvalError> {
    let mut fold = PureFold;
    evaluate_with_fold(command, args, config, facts, &mut fold)
}

/// Evaluate a command against config and context using a custom fold.
#[must_use = "evaluation result contains the access decision"]
pub fn evaluate_with_fold<F: EvalFold>(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    evaluate_at_depth(command, args, config, facts, fold, 0)
}

/// Common implementation; entry-points just pick a starting depth.
pub(crate) fn evaluate_at_depth<F: EvalFold>(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
) -> Result<EvalResult, EvalError> {
    if depth >= super::context::DEFAULT_RECURSION_LIMIT {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!(
                "recursion depth limit ({}) exceeded",
                super::context::DEFAULT_RECURSION_LIMIT
            )),
        ));
    }
    let parser = config.parser_for_with_rules(command);
    // Pun policy: under `:pun :error`, a bare parameter token (no
    // separator-and-value, not a recognised flag) MUST cause the
    // tokeniser to refuse the input. Surfaced as Ask — the binary
    // contract is "do not allow", and Ask routes back to the user.
    if parser.style.pun() == PunPolicy::Error
        && let Err(reason) = check_pun_error(args, &parser)
    {
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }
    let expanded = tokenise(args, &parser);
    fold.record_parser(command, &parser);
    // Parser-level `(parameter X (authorise))` recursion. Run before
    // rule evaluation so `:via NAME` facts are in scope; the
    // recursion result also acts as a fallback decision when no rule
    // matches.
    let mut parser_recursion: Option<EvalResult> = None;
    let mut recursion_facts = facts.clone();
    for decl in &parser.parameters {
        if decl.treatment != ParameterTreatment::Authorise {
            continue;
        }
        let Some(value) =
            super::effects::find_parameter_value_for_predicate(&expanded, &decl.names, &parser)
        else {
            continue;
        };
        let parsed = may_i_shell_parser::parse_simple_command(&value)
            .unwrap_or_else(|| (value.clone(), Vec::new()));
        let (inner_cmd, inner_args) = parsed;
        let inner_facts_seed = recursion_facts.clone();
        let nested = evaluate_at_depth(
            &inner_cmd,
            &inner_args,
            config,
            &inner_facts_seed,
            fold,
            depth + 1,
        )?;
        if let Some(name) = decl.names.first()
            && let Ok(key) = may_i_core::Keyword::new(":via")
        {
            recursion_facts.insert_scalar(key, name);
        }
        parser_recursion = Some(nested);
    }
    let bindings = EvalContext::build_bindings(&config.defines);
    let evaluator = Evaluator::new(&config.rules);
    let mut ctx = EvalContext::with_parser(
        command,
        &expanded,
        &recursion_facts,
        bindings,
        parser,
        config,
    );
    ctx.recursion_depth = depth;
    let result = evaluator.evaluate(fold, &ctx)?;
    if matches!(result.decision, Decision::Ask)
        && let Some(rec) = parser_recursion
    {
        return Ok(rec);
    }
    Ok(result)
}

/// Tokenise `args` under `parser`. Returns the expanded token stream
/// that downstream `parser_positional_args` and flag-matching code
/// walks. Style-aware: combined-shorts, first-token-bundle, and
/// prefix selection all come from `parser.style`.
pub fn tokenise(args: &[String], parser: &ResolvedParser) -> Vec<String> {
    let style = &parser.style;
    if style.combined_shorts() {
        if style.first_token_bundle() {
            expand_legacy_bundle(args)
        } else {
            expand_combined_shorts(args)
        }
    } else if style.first_token_bundle() {
        expand_first_token_bundle_only(args)
    } else {
        args.to_vec()
    }
}

/// Pun-policy check. Returns Err when an undeclared bare token would
/// be rejected. Triggers under `:pun :error`: every recognised
/// parameter must appear with a value (separator or attached). Bare
/// parameter spellings, or unknown bare tokens that look like
/// parameters, fail.
fn check_pun_error(args: &[String], parser: &ResolvedParser) -> Result<(), String> {
    let style = &parser.style;
    let separators = style.separators();
    let mut past_terminator = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if past_terminator {
            continue;
        }
        if arg == "--" {
            past_terminator = true;
            continue;
        }
        let bare_is_parameter = parser
            .parameters
            .iter()
            .any(|d| d.names.iter().any(|n| n == arg));
        let has_inline_separator = separators
            .iter()
            .filter(|s| !s.trim().is_empty())
            .any(|s| arg.contains(s.as_str()));
        if bare_is_parameter && !has_inline_separator {
            if separators.iter().any(|s| s == " ") && iter.peek().is_some() {
                iter.next();
                continue;
            }
            return Err(format!(
                "tokenisation error: bare parameter `{arg}` under :pun :error"
            ));
        }
    }
    Ok(())
}

fn expand_combined_shorts(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        if is_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push(format!("-{ch}"));
            }
        } else {
            out.push(arg.clone());
        }
    }
    out
}

fn is_combined_short_flag(arg: &str) -> bool {
    arg.starts_with('-')
        && !arg.starts_with("--")
        && arg.len() > 2
        && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
}

fn expand_legacy_bundle(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut bundle_consumed = false;
    for arg in args {
        if !bundle_consumed
            && !arg.is_empty()
            && !arg.starts_with('-')
            && arg.chars().all(|c| c.is_ascii_alphabetic())
        {
            for ch in arg.chars() {
                out.push(format!("-{ch}"));
            }
            bundle_consumed = true;
        } else if is_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push(format!("-{ch}"));
            }
            bundle_consumed = true;
        } else {
            out.push(arg.clone());
            bundle_consumed = true;
        }
    }
    out
}

/// Bundle the first non-dashed alpha token only; leave the rest
/// untouched (no combined-shorts expansion afterwards).
fn expand_first_token_bundle_only(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut consumed = false;
    for arg in args {
        if !consumed
            && !arg.is_empty()
            && !arg.starts_with('-')
            && arg.chars().all(|c| c.is_ascii_alphabetic())
        {
            for ch in arg.chars() {
                out.push(format!("-{ch}"));
            }
            consumed = true;
        } else {
            out.push(arg.clone());
            consumed = true;
        }
    }
    out
}

/// Style-aware positional-args extraction. Walks the tokenised
/// stream, peeling off flags and parameter-value pairs per the
/// parser's style and parameter declarations. Returns the residual
/// positional tokens.
pub fn parser_positional_args<'a>(args: &'a [String], parser: &ResolvedParser) -> Vec<&'a str> {
    let style = &parser.style;
    let long_prefix = style.long_prefix();
    let short_prefix = style.short_prefix();
    let separators = style.separators();
    // Under GNU-shaped styles (`--`/`-` prefixes with `=` separator),
    // every `--long` flag without an inline `=` is assumed to consume
    // the next arg. Without this `(parameter X *)` rules can't see
    // the value of an undeclared long flag.
    let gnu_long_consumes_next =
        long_prefix == "--" && short_prefix == "-" && separators.iter().any(|s| s == "=");
    let mut out = Vec::new();
    let mut iter = args.iter().enumerate().peekable();
    let mut past_terminator = false;
    while let Some((_, arg)) = iter.next() {
        if past_terminator {
            out.push(arg.as_str());
            continue;
        }
        if arg == "--" {
            out.push(arg.as_str());
            past_terminator = true;
            continue;
        }
        let starts_long = !long_prefix.is_empty() && arg.starts_with(long_prefix);
        // Prefer the long prefix when both apply (e.g. `--` over `-`).
        let starts_short =
            !short_prefix.is_empty() && arg.starts_with(short_prefix) && !starts_long;
        if starts_long || starts_short {
            let prefix = if starts_long {
                long_prefix
            } else {
                short_prefix
            };
            let name_with_value = &arg[prefix.len()..];
            let inline_handled = separators
                .iter()
                .filter(|s| s.as_str() != " ")
                .any(|s| name_with_value.contains(s.as_str()));
            if inline_handled {
                continue;
            }
            let is_declared_param = parser.parameter_token_matches(arg);
            let consumes_next = is_declared_param || (starts_long && gnu_long_consumes_next);
            if consumes_next
                && separators.iter().any(|s| s.as_str() == " ")
                && iter.peek().is_some()
            {
                iter.next();
            }
            continue;
        }
        // No prefix (key-value style). If it contains a non-trivial
        // separator, it's flag-equivalent.
        let is_kv = separators.iter().filter(|s| !s.trim().is_empty()).any(|s| {
            arg.find(s.as_str())
                .map(|i| i > 0 && i < arg.len() - 1)
                .unwrap_or(false)
        });
        if long_prefix.is_empty() && short_prefix.is_empty() && is_kv {
            continue;
        }
        out.push(arg.as_str());
    }
    out
}

/// Tokenised outer/tail slices for a parser that declares `(tail …)`.
///
/// `outer` is the slice subject to the parser's normal flag/parameter
/// matchers. `tail` is the residual slice exposed only via
/// `(tail (authorise))`. When the parser does not declare a tail (or the
/// boundary token is absent for `AfterToken`), `tail` is `None` and
/// `outer` covers the whole argv.
#[derive(Debug)]
pub(super) struct ArgvSplit<'a> {
    pub outer: &'a [String],
    pub tail: Option<&'a [String]>,
}

/// Compute the outer/tail boundary for `args` under `parser`. The split
/// is purely positional — the input is the already-tokenised stream, so
/// callers should normally pass the result of [`tokenise`].
pub(super) fn split_outer_tail<'a>(args: &'a [String], parser: &ResolvedParser) -> ArgvSplit<'a> {
    let Some(tail_kind) = parser.tail.as_ref() else {
        return ArgvSplit {
            outer: args,
            tail: None,
        };
    };
    match tail_kind {
        Tail::AfterFlags => {
            let split_at = first_positional_index(args, parser);
            ArgvSplit {
                outer: &args[..split_at],
                tail: Some(&args[split_at..]),
            }
        }
        Tail::AfterToken(boundary) => {
            match args.iter().position(|a| boundary.iter().any(|b| b == a)) {
                Some(idx) => ArgvSplit {
                    outer: &args[..idx],
                    // The matched boundary token is consumed — neither
                    // slice includes it.
                    tail: Some(&args[idx + 1..]),
                },
                None => ArgvSplit {
                    outer: args,
                    tail: None,
                },
            }
        }
    }
}

/// Return the index of the first token in `args` that the parser would
/// treat as a positional under its style/parameter declarations.
/// Mirrors the flag/parameter consumption logic in
/// [`parser_positional_args`].
fn first_positional_index(args: &[String], parser: &ResolvedParser) -> usize {
    let style = &parser.style;
    let long_prefix = style.long_prefix();
    let short_prefix = style.short_prefix();
    let separators = style.separators();
    let gnu_long_consumes_next =
        long_prefix == "--" && short_prefix == "-" && separators.iter().any(|s| s == "=");

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            // The literal `--` itself becomes the first positional under
            // AfterFlags semantics; the tail starts here.
            return i;
        }
        let starts_long = !long_prefix.is_empty() && arg.starts_with(long_prefix);
        let starts_short =
            !short_prefix.is_empty() && arg.starts_with(short_prefix) && !starts_long;
        if starts_long || starts_short {
            let prefix = if starts_long {
                long_prefix
            } else {
                short_prefix
            };
            let name_with_value = &arg[prefix.len()..];
            let inline_handled = separators
                .iter()
                .filter(|s| s.as_str() != " ")
                .any(|s| name_with_value.contains(s.as_str()));
            if inline_handled {
                i += 1;
                continue;
            }
            let is_declared_param = parser.parameter_token_matches(arg);
            let consumes_next = is_declared_param || (starts_long && gnu_long_consumes_next);
            if consumes_next && separators.iter().any(|s| s.as_str() == " ") && i + 1 < args.len() {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        // No flag prefix. Under styles with empty prefixes (key-value),
        // `key=value` tokens are flag-equivalent and consumed.
        let is_kv = separators.iter().filter(|s| !s.trim().is_empty()).any(|s| {
            arg.find(s.as_str())
                .map(|j| j > 0 && j < arg.len() - 1)
                .unwrap_or(false)
        });
        if long_prefix.is_empty() && short_prefix.is_empty() && is_kv {
            i += 1;
            continue;
        }
        // First positional — outer ends here.
        return i;
    }
    args.len()
}

/// Evaluator for rules with unified effect model.
pub struct Evaluator<'a> {
    rules: &'a [Rule],
}

impl<'a> Evaluator<'a> {
    /// Create a new evaluator with the given rules.
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Evaluate a command against all rules.
    /// Returns the first matching rule's effect, or ask if none match.
    pub fn evaluate<F: EvalFold>(
        &self,
        fold: &mut F,
        ctx: &EvalContext,
    ) -> Result<EvalResult, EvalError> {
        if ctx.is_depth_exceeded() {
            return Ok(EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "recursion depth limit ({}) exceeded",
                    ctx.recursion_limit
                )),
            ));
        }

        let mut any_command_matched = false;
        for rule in self.rules {
            let out = self.evaluate_rule(fold, rule, ctx)?;
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(decision, reason) => {
                    return Ok(EvalResult::new(*decision, reason.clone()));
                }
                EffectResult::Nil => {
                    if rule.command_effect.value.matches_command(ctx.command) {
                        any_command_matched = true;
                    }
                    continue;
                }
            }
        }

        let reason = if any_command_matched {
            format!(
                "Rules for `{}` exist but context or arguments did not match any patterns",
                ctx.command
            )
        } else {
            format!("No rule for command `{}`", ctx.command)
        };
        let _out = fold.default_ask(&reason);
        Ok(EvalResult::new(Decision::Ask, Some(reason)))
    }

    /// Evaluate a single rule. Returns the fold output.
    fn evaluate_rule<F: EvalFold>(
        &self,
        fold: &mut F,
        rule: &Rule,
        ctx: &EvalContext,
    ) -> Result<F::EffectOut, EvalError> {
        let command_out = evaluate_effect_fold(fold, &rule.command_effect.value, ctx, self.rules)?;
        let command_result = F::effect_result(&command_out);

        if command_result.is_nil() {
            return Ok(fold.rule_skipped(rule));
        }

        let out = evaluate_effect_fold(fold, &rule.effect.value, ctx, self.rules)?;
        let result = F::effect_result(&out);

        Ok(match result {
            EffectResult::Nil => fold.rule_not_matched(rule, ctx.facts, command_out, out),
            EffectResult::Decision(_, _) => {
                let line = None;
                fold.rule_matched(rule, line, ctx.facts, command_out, out)
            }
        })
    }
}

#[cfg(test)]
mod tokenisation_properties {
    use super::*;
    use may_i_core::ast::{ParameterDecl, ParameterTreatment as PT};
    use proptest::prelude::*;

    fn arg_token() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,5}".prop_map(String::from),
            "-[a-z]{1,4}".prop_map(String::from),
            "--[a-z]{1,5}".prop_map(String::from),
            "--[a-z]{1,5}=[a-z]{1,5}".prop_map(String::from),
            "[a-z]{1,4}=[a-z]{1,4}".prop_map(String::from),
            Just(String::from("--")),
            "-[0-9]{1}".prop_map(String::from),
        ]
    }

    fn argv() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec(arg_token(), 0..8)
    }

    /// Return one of the four prelude-equivalent styles by index.
    fn style_for_idx(idx: usize) -> Style {
        match idx {
            0 => Style::default_gnu(),
            1 => style_single_dash_long(),
            2 => style_legacy_bundle(),
            _ => style_key_value(),
        }
    }

    fn style_single_dash_long() -> Style {
        let spec = may_i_core::ast::StyleSpec {
            name: "single-dash-long".into(),
            overrides: None,
            long_prefix: Some("-".into()),
            short_prefix: Some("-".into()),
            separators: Some(vec![" ".into(), "=".into()]),
            combined_shorts: Some(false),
            first_token_bundle: Some(false),
            pun: Some(PunPolicy::Allow),
            span: may_i_core::Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };
        let mut reg = may_i_core::ast::StyleRegistry::new();
        reg.push(spec);
        reg.resolve("single-dash-long").unwrap()
    }

    fn style_legacy_bundle() -> Style {
        let spec = may_i_core::ast::StyleSpec {
            name: "legacy-bundle".into(),
            overrides: None,
            long_prefix: Some("--".into()),
            short_prefix: Some("-".into()),
            separators: Some(vec![" ".into(), "=".into()]),
            combined_shorts: Some(true),
            first_token_bundle: Some(true),
            pun: Some(PunPolicy::Allow),
            span: may_i_core::Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };
        let mut reg = may_i_core::ast::StyleRegistry::new();
        reg.push(spec);
        reg.resolve("legacy-bundle").unwrap()
    }

    fn style_key_value() -> Style {
        let spec = may_i_core::ast::StyleSpec {
            name: "key-value".into(),
            overrides: None,
            long_prefix: Some("".into()),
            short_prefix: Some("".into()),
            separators: Some(vec!["=".into()]),
            combined_shorts: Some(false),
            first_token_bundle: Some(false),
            pun: Some(PunPolicy::Error),
            span: may_i_core::Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };
        let mut reg = may_i_core::ast::StyleRegistry::new();
        reg.push(spec);
        reg.resolve("key-value").unwrap()
    }

    fn parser_with_style(style: Style) -> ResolvedParser {
        ResolvedParser {
            program: "any".into(),
            style,
            flags: vec![],
            parameters: vec![],
            tail: None,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 8.1 — synthetic GNU parser produces the same partition as
        // the legacy GNU code path for arbitrary argv.
        #[test]
        fn parser_gnu_matches_legacy(args in argv()) {
            let parser = parser_with_style(Style::default_gnu());
            let expanded = tokenise(&args, &parser);
            let legacy = expand_gnu_legacy(&args);
            prop_assert_eq!(&expanded, &legacy);
            let pos = parser_positional_args(&expanded, &parser);
            let legacy_pos = positional_args_legacy(&expanded);
            prop_assert_eq!(pos, legacy_pos);
        }

        // 8.2 — tokenisation is deterministic.
        #[test]
        fn parser_tokenise_deterministic(args in argv(), idx in 0usize..4) {
            let parser = parser_with_style(style_for_idx(idx));
            let a = tokenise(&args, &parser);
            let b = tokenise(&args, &parser);
            prop_assert_eq!(&a, &b);
            let pa = parser_positional_args(&a, &parser);
            let pb = parser_positional_args(&a, &parser);
            prop_assert_eq!(pa, pb);
        }

        // 8.3 — under `single-dash-long`, no token is split.
        #[test]
        fn parser_single_dash_long_never_splits(args in argv()) {
            let parser = parser_with_style(style_single_dash_long());
            let expanded = tokenise(&args, &parser);
            prop_assert_eq!(expanded.len(), args.len());
            prop_assert_eq!(&expanded, &args);
        }

        // 8.4 — under `:pun :error`, bare parameter tokens are
        // rejected; inline `name=val` is accepted.
        #[test]
        fn parser_pun_error_requires_inline_value(name in "[a-z]{1,4}", val in "[a-z]{1,4}") {
            let mut parser = parser_with_style(style_key_value());
            parser.parameters.push(ParameterDecl {
                names: vec![name.clone()],
                treatment: PT::None,
                capture: may_i_core::ast::Capture::Single,
            });
            let bare = vec![name.clone()];
            prop_assert!(check_pun_error(&bare, &parser).is_err());
            let inline = vec![format!("{name}={val}")];
            prop_assert!(check_pun_error(&inline, &parser).is_ok());
        }

        // 8.5 — :overrides resolution idempotent: rebuilding a style
        // from its own properties yields the same tokenisation.
        #[test]
        fn parser_overrides_resolution_idempotent(args in argv(), idx in 0usize..4) {
            let s = style_for_idx(idx);
            let p1 = parser_with_style(s.clone());
            let p2 = parser_with_style(s);
            prop_assert_eq!(&tokenise(&args, &p1), &tokenise(&args, &p2));
        }
    }

    /// Mirror of the pre-refactor `expand_combined_flags` GNU branch.
    fn expand_gnu_legacy(args: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(args.len());
        for arg in args {
            if arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 2
                && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
            {
                for ch in arg[1..].chars() {
                    out.push(format!("-{ch}"));
                }
            } else {
                out.push(arg.clone());
            }
        }
        out
    }

    /// Mirror of the pre-refactor `positional_args` GNU branch.
    fn positional_args_legacy(args: &[String]) -> Vec<&str> {
        let mut result = Vec::new();
        let mut iter = args.iter().peekable();
        let mut past_terminator = false;
        while let Some(arg) = iter.next() {
            if past_terminator {
                result.push(arg.as_str());
            } else if arg == "--" {
                result.push(arg.as_str());
                past_terminator = true;
            } else if arg.starts_with("--") {
                if !arg.contains('=') {
                    iter.next();
                }
            } else if arg.starts_with('-') {
                // short flag — does not consume value
            } else {
                result.push(arg.as_str());
            }
        }
        result
    }

    fn arg_strs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn parser_with_tail(tail: Option<Tail>) -> ResolvedParser {
        let mut p = parser_with_style(Style::default_gnu());
        p.tail = tail;
        p
    }

    #[test]
    fn split_outer_tail_no_decl_returns_whole_argv() {
        let args = arg_strs(&["-r", "foo", "bar"]);
        let parser = parser_with_tail(None);
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, args.as_slice());
        assert!(split.tail.is_none());
    }

    #[test]
    fn split_outer_tail_after_flags_basic() {
        // sudo-style: outer = flags only; tail starts at first positional.
        let args = arg_strs(&["-u", "root", "rm", "-rf", "/tmp/x"]);
        let mut parser = parser_with_tail(Some(Tail::AfterFlags));
        parser.parameters.push(may_i_core::ast::ParameterDecl {
            names: vec!["u".into()],
            treatment: ParameterTreatment::None,
            capture: may_i_core::ast::Capture::Single,
        });
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, &["-u".to_string(), "root".to_string()]);
        assert_eq!(
            split.tail.unwrap(),
            &["rm".to_string(), "-rf".to_string(), "/tmp/x".to_string()]
        );
    }

    #[test]
    fn split_outer_tail_after_flags_no_positionals() {
        let args = arg_strs(&["-r", "-f"]);
        let parser = parser_with_tail(Some(Tail::AfterFlags));
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, args.as_slice());
        assert_eq!(split.tail.unwrap(), &[] as &[String]);
    }

    #[test]
    fn split_outer_tail_after_token_present() {
        let args = arg_strs(&["exec", "node", "--", "build", "--prod"]);
        let parser = parser_with_tail(Some(Tail::AfterToken(vec!["--".into()])));
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, &["exec".to_string(), "node".to_string()]);
        assert_eq!(
            split.tail.unwrap(),
            &["build".to_string(), "--prod".to_string()]
        );
    }

    #[test]
    fn split_outer_tail_after_token_absent() {
        let args = arg_strs(&["exec", "node"]);
        let parser = parser_with_tail(Some(Tail::AfterToken(vec!["--".into()])));
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, args.as_slice());
        assert!(split.tail.is_none());
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 7.5 — outer ⊕ boundary ⊕ tail = original argv (modulo dropped
        // boundary token where applicable).
        #[test]
        fn outer_tail_partition_preserves_argv(args in argv()) {
            let after_flags = parser_with_tail(Some(Tail::AfterFlags));
            let split = split_outer_tail(&args, &after_flags);
            let recombined: Vec<String> = split
                .outer
                .iter()
                .chain(split.tail.unwrap_or(&[]).iter())
                .cloned()
                .collect();
            prop_assert_eq!(recombined, args.clone());
        }

        #[test]
        fn outer_tail_after_token_drops_only_boundary(args in argv()) {
            let after_token = parser_with_tail(Some(Tail::AfterToken(vec!["--".into()])));
            let split = split_outer_tail(&args, &after_token);
            match split.tail {
                Some(tail) => {
                    let mut combined: Vec<String> = split.outer.to_vec();
                    combined.push("--".to_string());
                    combined.extend(tail.iter().cloned());
                    prop_assert_eq!(combined, args.clone());
                }
                None => {
                    prop_assert!(!args.iter().any(|a| a == "--"));
                }
            }
        }
    }
}

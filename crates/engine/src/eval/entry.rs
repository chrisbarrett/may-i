#[cfg(test)]
use may_i_core::ast::Style;
use may_i_core::ast::{EffectResult, ParameterTreatment, PunPolicy, ResolvedParser, Rule};
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser::Dialect;

use crate::fold::{EvalFold, PureFold};
use crate::{DisplaySafe, EvalError, EvalResult};

use super::context::EvalContext;
use super::decompose::Argv;
use super::effects::evaluate_effect_fold;

/// Evaluate a command against config and context using PureFold.
/// This is the main entry point for evaluation.
///
/// `args` are taken at face value (no expansion provenance): callers
/// passing a pre-split argv assert each token is a literal. The shell
/// entry point (`evaluate_command`) threads per-token provenance from
/// the parsed words instead.
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
/// See [`evaluate`] for the literal-args caveat.
#[must_use = "evaluation result contains the access decision"]
pub fn evaluate_with_fold<F: EvalFold>(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    let expansions = vec![None; args.len()];
    evaluate_at_depth(
        command,
        Argv::new(args, &expansions),
        config,
        facts,
        Dialect::Bash,
        fold,
        0,
    )
}

/// Common implementation; entry-points just pick a starting depth.
/// `argv` carries the argument tokens with their per-token expansion
/// provenance.
pub(crate) fn evaluate_at_depth<F: EvalFold>(
    command: &str,
    argv: Argv,
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    dialect: Dialect,
    fold: &mut F,
    depth: usize,
) -> Result<EvalResult, EvalError> {
    let Argv {
        args,
        expansions: arg_expansions,
    } = argv;
    if depth >= super::context::DEFAULT_RECURSION_LIMIT {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(format!(
                "recursion depth limit ({}) exceeded",
                super::context::DEFAULT_RECURSION_LIMIT
            ))),
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
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(reason)),
        ));
    }
    let (expanded, expanded_expansions) = tokenise(args, arg_expansions, &parser);
    fold.record_parser(command, &parser);
    // Surface each undeclared-long-flag arity guess as a Trace Advisory:
    // the tokeniser made a guess, so make it observable regardless of
    // whether any rule consults the residual. Advisories never change the
    // Decision.
    for guess in arity_guess_advisories(&expanded, &parser) {
        fold.arity_guess_advisory(&guess.flag, &guess.consumed);
    }
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
        let Some((value, value_expansion)) = super::effects::find_parameter_value_for_predicate(
            &expanded,
            &expanded_expansions,
            &decl.names,
            &parser,
        ) else {
            continue;
        };
        let inner_facts_seed = recursion_facts.clone();
        let nested = super::command::evaluate_authorised_string(
            &value,
            Some(config),
            &inner_facts_seed,
            fold,
            depth + 1,
            None,
            dialect,
        )?;
        // An expansion-bearing captured value re-parses as unfaithful
        // text; its recursion result cannot prove an allow (asymmetric
        // soundness — floor to ask, never widen).
        let nested = match value_expansion {
            Some(display) if nested.decision == Decision::Allow => EvalResult::new(
                Decision::Ask,
                Some(DisplaySafe::new(
                    super::command::unresolved_expansion_reason(&[display]),
                )),
            ),
            _ => nested,
        };
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
        expanded_expansions,
        &recursion_facts,
        bindings,
        parser,
        config,
    );
    ctx.recursion_depth = depth;
    ctx.dialect = dialect;
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
/// walks, paired with per-token expansion provenance: a derived token
/// (e.g. `-a` split out of `-abc`) inherits its source token's
/// provenance. Style-aware: combined-shorts, first-token-bundle, and
/// prefix selection all come from `parser.style`.
pub(crate) fn tokenise(
    args: &[String],
    expansions: &[super::decompose::Expansion],
    parser: &ResolvedParser,
) -> (Vec<String>, Vec<super::decompose::Expansion>) {
    debug_assert_eq!(args.len(), expansions.len());
    let style = &parser.style;
    let expanded = if style.combined_shorts() {
        if style.first_token_bundle() {
            expand_legacy_bundle_pairs(args, expansions)
        } else {
            expand_combined_shorts_pairs(args, expansions)
        }
    } else if style.first_token_bundle() {
        expand_first_token_bundle_only_pairs(args, expansions)
    } else {
        args.iter()
            .cloned()
            .zip(expansions.iter().cloned())
            .collect()
    };
    expanded.into_iter().unzip()
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

type TokenPair = (String, super::decompose::Expansion);

fn expand_combined_shorts_pairs(
    args: &[String],
    expansions: &[super::decompose::Expansion],
) -> Vec<TokenPair> {
    let mut out = Vec::with_capacity(args.len());
    for (arg, exp) in args.iter().zip(expansions) {
        if is_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push((format!("-{ch}"), exp.clone()));
            }
        } else {
            out.push((arg.clone(), exp.clone()));
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

fn expand_legacy_bundle_pairs(
    args: &[String],
    expansions: &[super::decompose::Expansion],
) -> Vec<TokenPair> {
    let mut out = Vec::with_capacity(args.len());
    let mut bundle_consumed = false;
    for (arg, exp) in args.iter().zip(expansions) {
        if !bundle_consumed
            && !arg.is_empty()
            && !arg.starts_with('-')
            && arg.chars().all(|c| c.is_ascii_alphabetic())
        {
            for ch in arg.chars() {
                out.push((format!("-{ch}"), exp.clone()));
            }
            bundle_consumed = true;
        } else if is_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push((format!("-{ch}"), exp.clone()));
            }
            bundle_consumed = true;
        } else {
            out.push((arg.clone(), exp.clone()));
            bundle_consumed = true;
        }
    }
    out
}

/// Bundle the first non-dashed alpha token only; leave the rest
/// untouched (no combined-shorts expansion afterwards).
fn expand_first_token_bundle_only_pairs(
    args: &[String],
    expansions: &[super::decompose::Expansion],
) -> Vec<TokenPair> {
    let mut out = Vec::with_capacity(args.len());
    let mut consumed = false;
    for (arg, exp) in args.iter().zip(expansions) {
        if !consumed
            && !arg.is_empty()
            && !arg.starts_with('-')
            && arg.chars().all(|c| c.is_ascii_alphabetic())
        {
            for ch in arg.chars() {
                out.push((format!("-{ch}"), exp.clone()));
            }
            consumed = true;
        } else {
            out.push((arg.clone(), exp.clone()));
            consumed = true;
        }
    }
    out
}

/// Style-aware positional-args extraction. Walks the tokenised
/// stream, peeling off flags and parameter-value pairs per the
/// parser's style and parameter declarations. Returns the residual
/// positional tokens.
#[cfg(test)]
pub(crate) fn parser_positional_args<'a>(
    args: &'a [String],
    parser: &ResolvedParser,
) -> Vec<&'a str> {
    parser_positional_indices(args, parser)
        .into_iter()
        .map(|i| args[i].as_str())
        .collect()
}

/// A guess the gnu tokeniser made about an undeclared long flag's
/// arity: `flag` consumed `consumed` as its value because `consumed`
/// looked like a plausible (non-flag) value rather than a declared
/// parameter's value. Surfaced as a Trace Advisory; never alters a
/// Decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArityGuess {
    pub flag: String,
    pub consumed: String,
}

/// True when `token` could be the value of a preceding undeclared long
/// flag whose arity must be guessed. A token is **not** a plausible
/// value (i.e. it is flag-shaped, so it is left in the residual) when it
/// begins with the style's long or short prefix and the character
/// immediately after that prefix is an ASCII letter. The `--` flag-stop
/// is never a plausible value. Digit-led tokens (`-5`), a bare `-`, and
/// prefix-less tokens are plausible values.
fn next_token_is_plausible_value(token: &str, long_prefix: &str, short_prefix: &str) -> bool {
    if token == "--" {
        return false;
    }
    for prefix in [long_prefix, short_prefix] {
        if !prefix.is_empty()
            && token.starts_with(prefix)
            && token[prefix.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
        {
            return false;
        }
    }
    true
}

/// Decide whether a flag token `arg` consumes its successor, and whether
/// that consumption is an undeclared-gnu arity *guess* (vs an
/// author-declared arity). Returns `(consumes_next, is_guess)`.
///
/// Sole owner of the consume rule for prefixed flags: both the residual
/// walk ([`positional_indices_walk`]) and the outer-split scan
/// ([`first_positional_index`]) call this, so the two can never drift.
/// `next_plausible` is whether the successor is a plausible value
/// ([`next_token_is_plausible_value`]).
fn long_flag_consumption(
    parser: &ResolvedParser,
    arg: &str,
    starts_long: bool,
    gnu_long_consumes_next: bool,
    next_plausible: bool,
) -> (bool, bool) {
    let is_declared_param = parser.parameter_token_matches(arg);
    let is_declared_flag = parser.flag_token_matches(arg);
    // Declared parameters consume regardless of the next token's shape; a
    // declared boolean `(flag …)` is value-less and never consumes; the
    // undeclared gnu guess consumes only a plausible value.
    let is_guess = !is_declared_param && !is_declared_flag && starts_long && gnu_long_consumes_next;
    let consumes_next = is_declared_param || (is_guess && next_plausible);
    (consumes_next, is_guess)
}

/// Index-reporting form of [`parser_positional_args`]: returns the
/// positions in `args` of the residual positional tokens, so callers can
/// pair each token with side data aligned to the same argv (expansion
/// provenance).
pub(crate) fn parser_positional_indices(args: &[String], parser: &ResolvedParser) -> Vec<usize> {
    positional_indices_walk(args, parser).0
}

/// Collect the arity guesses the gnu tokeniser makes for undeclared long
/// flags over `args`: each is an undeclared, gnu-shaped long flag
/// immediately followed by a plausible (non-flag) value the tokeniser
/// consumes. Shares the consumption walk with
/// [`parser_positional_indices`] so the guess set never drifts from the
/// residual it explains.
pub(crate) fn arity_guess_advisories(args: &[String], parser: &ResolvedParser) -> Vec<ArityGuess> {
    positional_indices_walk(args, parser).1
}

/// Shared residual walk: returns the residual positional indices paired
/// with every undeclared-long-flag arity guess (a consumed plausible
/// value) made along the way.
fn positional_indices_walk(
    args: &[String],
    parser: &ResolvedParser,
) -> (Vec<usize>, Vec<ArityGuess>) {
    let style = &parser.style;
    let long_prefix = style.long_prefix();
    let short_prefix = style.short_prefix();
    let separators = style.separators();
    // Under GNU-shaped styles (`--`/`-` prefixes with `=` separator), an
    // undeclared `--long` flag without an inline `=` may consume the next
    // arg as its value — but only when that arg is a plausible value
    // (not itself flag-shaped, not the `--` flag-stop). Declared
    // parameters consume their next arg unconditionally (author-asserted
    // arity).
    let gnu_long_consumes_next =
        long_prefix == "--" && short_prefix == "-" && separators.iter().any(|s| s == "=");
    let space_separated = separators.iter().any(|s| s.as_str() == " ");
    let mut out = Vec::new();
    let mut guesses = Vec::new();
    let mut iter = args.iter().enumerate().peekable();
    let mut past_terminator = false;
    while let Some((i, arg)) = iter.next() {
        if past_terminator {
            out.push(i);
            continue;
        }
        if arg == "--" {
            out.push(i);
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
            let next_plausible = iter.peek().is_some_and(|(_, next)| {
                next_token_is_plausible_value(next, long_prefix, short_prefix)
            });
            let (consumes_next, is_guess) = long_flag_consumption(
                parser,
                arg,
                starts_long,
                gnu_long_consumes_next,
                next_plausible,
            );
            if consumes_next
                && space_separated
                && let Some((_, next)) = iter.peek()
            {
                if is_guess {
                    guesses.push(ArityGuess {
                        flag: arg.clone(),
                        consumed: (*next).clone(),
                    });
                }
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
        out.push(i);
    }
    (out, guesses)
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
///
/// Reads `parser.flags_mode` as the source of truth; the legacy
/// `parser.tail` field is no longer consulted (parser-named-bindings
/// section 5: `flags_mode` supersedes it).
pub(super) fn split_outer_tail<'a>(args: &'a [String], parser: &ResolvedParser) -> ArgvSplit<'a> {
    use may_i_core::ast::FlagsMode;
    match &parser.flags_mode {
        // `permute`: outer covers the whole argv; no recurse target
        // unless the parser declares `(rest …)`. The legacy callers
        // treat `tail = None` as "no boundary" and walk the whole
        // argv, so preserve that shape here.
        FlagsMode::Permute => ArgvSplit {
            outer: args,
            tail: None,
        },
        // `posix`: outer ends at the first positional, matching the
        // historic `(tail (after :flags))` boundary.
        FlagsMode::Posix => {
            let split_at = first_positional_index(args, parser);
            ArgvSplit {
                outer: &args[..split_at],
                tail: Some(&args[split_at..]),
            }
        }
        // `until STR…`: outer ends before the first occurrence of any
        // boundary token; the boundary token itself is consumed.
        FlagsMode::Until(boundary) => {
            match args.iter().position(|a| boundary.iter().any(|b| b == a)) {
                Some(idx) => ArgvSplit {
                    outer: &args[..idx],
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
            let next_plausible = i + 1 < args.len()
                && next_token_is_plausible_value(&args[i + 1], long_prefix, short_prefix);
            let (consumes_next, _is_guess) = long_flag_consumption(
                parser,
                arg,
                starts_long,
                gnu_long_consumes_next,
                next_plausible,
            );
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
    ///
    /// Runs every rule whose command pattern matches the input, collects
    /// each non-Nil decision, and returns the strictest under the lattice
    /// `Allow < Ask < Deny`. When two or more rules tie on the strictest
    /// decision, distinct reasons are deduplicated, sorted lexically, and
    /// joined with `"; "` so the result does not depend on rule order.
    /// If no rule produces a decision, returns `Ask`.
    pub fn evaluate<F: EvalFold>(
        &self,
        fold: &mut F,
        ctx: &EvalContext,
    ) -> Result<EvalResult, EvalError> {
        if ctx.is_depth_exceeded() {
            return Ok(EvalResult::new(
                Decision::Ask,
                Some(DisplaySafe::new(format!(
                    "recursion depth limit ({}) exceeded",
                    ctx.recursion_limit
                ))),
            ));
        }

        // (match_idx, decision, reason). Match indices count `rule_matched`
        // calls in evaluation order so folds can correlate with their
        // per-scope trace entries.
        let mut matches: Vec<(usize, Decision, Option<String>)> = Vec::new();
        let mut match_counter: usize = 0;
        let mut any_command_matched = false;
        for rule in self.rules.iter() {
            ctx.unresolved.borrow_mut().clear();
            let out = self.evaluate_rule(fold, rule, ctx)?;
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(decision, reason) => {
                    let match_idx = match_counter;
                    match_counter += 1;
                    // Asymmetric soundness: an `:allow` that relied on a
                    // match against an expansion-bearing word rests on a
                    // constraint that is not provable for the runtime
                    // value — floor it to `:ask`, naming the word(s).
                    // `:ask`/`:deny` decisions stand (uncertainty only
                    // ever tightens).
                    let unresolved = ctx.unresolved.borrow();
                    if *decision == Decision::Allow && !unresolved.is_empty() {
                        let reason = super::command::unresolved_expansion_reason(&unresolved);
                        fold.unresolved_floor(&unresolved);
                        matches.push((match_idx, Decision::Ask, Some(reason)));
                    } else {
                        matches.push((match_idx, *decision, reason.clone()));
                    }
                }
                EffectResult::Nil => {
                    if rule.command_effect.value.matches_command(ctx.command) {
                        any_command_matched = true;
                    }
                }
            }
        }

        if !matches.is_empty() {
            let strictest = matches.iter().map(|(_, d, _)| *d).max().unwrap();
            let tied: Vec<&(usize, Decision, Option<String>)> =
                matches.iter().filter(|(_, d, _)| *d == strictest).collect();
            let tied_match_indices: Vec<usize> = tied.iter().map(|(i, _, _)| *i).collect();
            let mut distinct_reasons: Vec<&str> =
                tied.iter().filter_map(|(_, _, r)| r.as_deref()).collect();
            distinct_reasons.sort();
            distinct_reasons.dedup();
            let reason = if distinct_reasons.is_empty() {
                None
            } else {
                Some(DisplaySafe::new(distinct_reasons.join("; ")))
            };
            let reason_source_match_index = tied
                .iter()
                .find(|(_, _, r)| r.is_some())
                .map(|(i, _, _)| *i);
            fold.rules_combined(&tied_match_indices, reason_source_match_index);
            return Ok(EvalResult::new(strictest, reason));
        }

        let command = ctx.command;
        let reason = DisplaySafe::new(if any_command_matched {
            format!(
                "Rules for `{command}` exist but context or arguments did not match any patterns"
            )
        } else {
            format!("No rule for command `{command}`")
        });
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
            positionals: vec![],
            flags_mode: may_i_core::ast::FlagsMode::Permute,
            rest: None,
            binding_spans: Default::default(),
        }
    }

    /// Tokenise with all-literal expansion provenance, returning only
    /// the token texts (the shape the pre-provenance tests asserted on).
    fn tokenise_lit(args: &[String], parser: &ResolvedParser) -> Vec<String> {
        tokenise(args, &vec![None; args.len()], parser).0
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 8.1 — synthetic GNU parser produces the same partition as
        // the legacy GNU code path for arbitrary argv.
        #[test]
        fn parser_gnu_matches_legacy(args in argv()) {
            let parser = parser_with_style(Style::default_gnu());
            let expanded = tokenise_lit(&args, &parser);
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
            let a = tokenise_lit(&args, &parser);
            let b = tokenise_lit(&args, &parser);
            prop_assert_eq!(&a, &b);
            let pa = parser_positional_args(&a, &parser);
            let pb = parser_positional_args(&a, &parser);
            prop_assert_eq!(pa, pb);
        }

        // 8.3 — under `single-dash-long`, no token is split.
        #[test]
        fn parser_single_dash_long_never_splits(args in argv()) {
            let parser = parser_with_style(style_single_dash_long());
            let expanded = tokenise_lit(&args, &parser);
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
                shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
                capture: may_i_core::ast::Capture::Single,
                binding: None,
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
            prop_assert_eq!(&tokenise_lit(&args, &p1), &tokenise_lit(&args, &p2));
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

    /// Whether `tok` is flag-shaped under the default GNU style: it
    /// begins with `--`/`-` and the char after the prefix is a letter.
    /// Independent re-derivation of the value-shape rule for the oracle.
    fn gnu_flag_shaped(tok: &str) -> bool {
        if let Some(rest) = tok.strip_prefix("--") {
            return rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        }
        if let Some(rest) = tok.strip_prefix('-') {
            return rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        }
        false
    }

    /// Independent GNU oracle for the residual partition under the
    /// value-shape rule: an undeclared `--long` flag consumes the next
    /// token only when it is a plausible value (not `--`, not flag-shaped);
    /// the `--` flag-stop is never consumed.
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
                // Inline `=` value → value-less; otherwise consume the next
                // token only when it is a plausible value.
                if !arg.contains('=')
                    && iter
                        .peek()
                        .is_some_and(|n| *n != "--" && !gnu_flag_shaped(n))
                {
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

    fn gnu_parser_with_param(names: &[&str]) -> ResolvedParser {
        let mut p = parser_with_style(Style::default_gnu());
        if !names.is_empty() {
            p.parameters.push(ParameterDecl {
                names: names.iter().map(|s| s.to_string()).collect(),
                treatment: PT::None,
                shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
                capture: may_i_core::ast::Capture::Single,
                binding: None,
            });
        }
        p
    }

    // 1.1 — an undeclared long flag does NOT consume a flag-shaped next
    // token: `--quiet --bin may-i -- eval` keeps the `run, --, eval`
    // adjacency that `(positional "run" "--")` matches against.
    #[test]
    fn undeclared_long_flag_does_not_consume_following_flag() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["run", "--quiet", "--bin", "may-i", "--", "eval"]);
        // `--quiet` is value-less (next is the flag-shaped `--bin`); `--bin`
        // consumes the plausible value `may-i`.
        assert_eq!(
            parser_positional_args(&args, &parser),
            vec!["run", "--", "eval"]
        );
    }

    // 1.1 — an undeclared long flag before a bare subcommand still guesses
    // and consumes it (a plausible, non-flag value).
    #[test]
    fn undeclared_long_flag_consumes_bare_subcommand() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["--release", "build"]);
        assert!(parser_positional_args(&args, &parser).is_empty());
    }

    // 1.1 — an undeclared long flag consumes a plausible (non-flag) value.
    #[test]
    fn undeclared_long_flag_consumes_plausible_value() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["--output", "report.txt"]);
        assert!(parser_positional_args(&args, &parser).is_empty());
    }

    // 1.2 — a short-flag-shaped successor (`-v`) is not a plausible value,
    // so the undeclared long flag does not consume it (covers the
    // short-prefix arm of `next_token_is_plausible_value`).
    #[test]
    fn undeclared_long_flag_does_not_consume_short_flag_successor() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["--output", "-v", "file"]);
        assert_eq!(parser_positional_args(&args, &parser), vec!["file"]);
        assert!(arity_guess_advisories(&args, &parser).is_empty());
    }

    // 1.3 — the value-shape guard also governs the outer/tail split
    // (`first_positional_index`), which shares `long_flag_consumption`:
    // `--quiet` keeps the flag-shaped `--bin` in the outer slice, and
    // `--bin` consumes `may-i`, so the tail starts at `build`.
    #[test]
    fn first_positional_index_honours_value_shape_guard() {
        let parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Posix);
        let args = arg_strs(&["--quiet", "--bin", "may-i", "build"]);
        let split = split_outer_tail(&args, &parser);
        assert_eq!(
            split.outer,
            &[
                "--quiet".to_string(),
                "--bin".to_string(),
                "may-i".to_string()
            ]
        );
        assert_eq!(split.tail.unwrap(), &["build".to_string()]);
    }

    // 1.4 — a negative-number token is a plausible value: consumed.
    #[test]
    fn undeclared_long_flag_consumes_negative_number() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["--threshold", "-5", "input"]);
        assert_eq!(parser_positional_args(&args, &parser), vec!["input"]);
    }

    // 1.4 — a declared parameter consumes a flag-shaped value
    // (author-asserted arity).
    #[test]
    fn declared_parameter_consumes_flag_shaped_value() {
        let parser = gnu_parser_with_param(&["e", "regexp"]);
        let args = arg_strs(&["--regexp", "--foo", "file"]);
        assert_eq!(parser_positional_args(&args, &parser), vec!["file"]);
    }

    // 1.4 — a flag declared as a boolean `(flag …)` is value-less and
    // does not consume its successor (author-asserted arity), so the bare
    // subcommand survives in the residual.
    #[test]
    fn declared_boolean_flag_does_not_consume_successor() {
        let mut parser = parser_with_style(Style::default_gnu());
        parser
            .flags
            .push(may_i_core::ast::FlagDecl::new(vec!["release".into()]));
        let args = arg_strs(&["--release", "build"]);
        assert_eq!(parser_positional_args(&args, &parser), vec!["build"]);
        // No guess: the arity was declared, not guessed.
        assert!(arity_guess_advisories(&args, &parser).is_empty());
    }

    // 2.1 — an undeclared flag must not absorb the `--` flag-stop; the
    // terminator semantics hold and `value` becomes a positional.
    #[test]
    fn undeclared_long_flag_does_not_consume_flag_stop() {
        let parser = gnu_parser_with_param(&[]);
        let args = arg_strs(&["--undeclared", "--", "value"]);
        assert_eq!(parser_positional_args(&args, &parser), vec!["--", "value"]);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 5.1 — a declared parameter always consumes its successor token
        // regardless of the successor's shape (author-asserted arity).
        // The undeclared value-shape residual is covered exhaustively by
        // `parser_gnu_matches_legacy` against the independent oracle.
        // `name` is multi-character so its token form is the long `--name`
        // (single-char names canonicalise to a short `-name`).
        #[test]
        fn declared_parameter_always_consumes_successor(name in "[a-z]{2,5}", next in arg_token()) {
            let parser = gnu_parser_with_param(&[&name]);
            let args = vec![format!("--{name}"), next];
            prop_assert!(parser_positional_args(&args, &parser).is_empty());
        }

        // 5.1 — an undeclared long flag never consumes the `--` flag-stop;
        // it always survives in the residual as the terminator.
        #[test]
        fn undeclared_long_flag_never_eats_flag_stop(name in "[a-z]{1,5}", tail in argv()) {
            let parser = gnu_parser_with_param(&[]);
            let mut args = vec![format!("--{name}"), "--".to_string()];
            args.extend(tail);
            let residual = parser_positional_args(&args, &parser);
            prop_assert!(residual.contains(&"--"));
        }
    }

    // 3.1 — an arity guess on a plausible value is recorded; no guess for
    // a flag-shaped successor or a declared parameter.
    #[test]
    fn arity_guess_advisories_records_only_real_guesses() {
        let parser = gnu_parser_with_param(&[]);
        let guesses = arity_guess_advisories(&arg_strs(&["--output", "report.txt"]), &parser);
        assert_eq!(
            guesses,
            vec![ArityGuess {
                flag: "--output".into(),
                consumed: "report.txt".into(),
            }]
        );

        // Flag-shaped / absent successors → no guess.
        assert!(arity_guess_advisories(&arg_strs(&["--verbose", "--quiet"]), &parser).is_empty());

        // `--` flag-stop → no guess.
        assert!(
            arity_guess_advisories(&arg_strs(&["--undeclared", "--", "x"]), &parser).is_empty()
        );

        // Declared parameter → no guess (arity asserted, not guessed).
        let declared = gnu_parser_with_param(&["output"]);
        assert!(
            arity_guess_advisories(&arg_strs(&["--output", "report.txt"]), &declared).is_empty()
        );
    }

    fn parser_with_flags_mode(mode: may_i_core::ast::FlagsMode) -> ResolvedParser {
        let mut p = parser_with_style(Style::default_gnu());
        p.flags_mode = mode;
        p
    }

    #[test]
    fn split_outer_tail_no_decl_returns_whole_argv() {
        let args = arg_strs(&["-r", "foo", "bar"]);
        let parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Permute);
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, args.as_slice());
        assert!(split.tail.is_none());
    }

    #[test]
    fn split_outer_tail_after_flags_basic() {
        // sudo-style: outer = flags only; tail starts at first positional.
        let args = arg_strs(&["-u", "root", "rm", "-rf", "/tmp/x"]);
        let mut parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Posix);
        parser.parameters.push(may_i_core::ast::ParameterDecl {
            names: vec!["u".into()],
            treatment: ParameterTreatment::None,
            shape_form: may_i_core::ast::ParamShapeForm::Unannotated,
            capture: may_i_core::ast::Capture::Single,
            binding: None,
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
        let parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Posix);
        let split = split_outer_tail(&args, &parser);
        assert_eq!(split.outer, args.as_slice());
        assert_eq!(split.tail.unwrap(), &[] as &[String]);
    }

    #[test]
    fn split_outer_tail_after_token_present() {
        let args = arg_strs(&["exec", "node", "--", "build", "--prod"]);
        let parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Until(vec!["--".into()]));
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
        let parser = parser_with_flags_mode(may_i_core::ast::FlagsMode::Until(vec!["--".into()]));
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
            let after_flags = parser_with_flags_mode(may_i_core::ast::FlagsMode::Posix);
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
            let after_token = parser_with_flags_mode(may_i_core::ast::FlagsMode::Until(vec!["--".into()]));
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

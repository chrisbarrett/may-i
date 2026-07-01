use may_i_core::ast::{Config, Effect, EffectResult};
use may_i_core::{ContextFacts, Decision, EntryEnv, Keyword};
use may_i_shell_parser as parser;

use crate::fold::{EvalFold, PureFold};
use crate::{DisplaySafe, EvalError, EvalResult, SegmentDecision};

use super::context::{DEFAULT_RECURSION_LIMIT, EnvScope, EvalContext};
use super::decompose::{Argv, EmbeddedKind, EvalUnit, SubstitutionOrigin, decompose};
use super::effects::evaluate_effect_fold;
use super::entry::evaluate_at_depth;

/// Evaluate a capability's fact-conditioned decision expression against
/// the active facts with an empty binding environment (design D6). Reuses
/// the rule-body `Effect` evaluator; a `Nil` result (e.g. a `(when …)`
/// whose predicate did not match) yields `None`, meaning "no contribution".
/// Argv/binding constructs are rejected at load time, so the empty
/// command/args context never affects a well-formed capability.
fn capability_decision(
    decision: &Effect,
    config: &Config,
    facts: &ContextFacts,
    env_scope: Option<EnvScope>,
) -> Option<(Decision, Option<String>)> {
    let no_args: [String; 0] = [];
    let bindings = EvalContext::build_bindings(&config.defines);
    let mut ctx = EvalContext::new("", &no_args, facts, bindings);
    ctx.env_scope = env_scope;
    let mut pure = PureFold;
    match evaluate_effect_fold(&mut pure, decision, &ctx, &config.rules) {
        Ok(EffectResult::Decision(d, r)) => Some((d, r)),
        Ok(EffectResult::Nil) | Err(_) => None,
    }
}

/// Meet two `(decision, reason)` contributions strictest-wins, keeping the
/// reason of the strictest. Ties keep the incumbent.
fn meet_decision(
    acc: Option<(Decision, Option<String>)>,
    next: (Decision, Option<String>),
) -> Option<(Decision, Option<String>)> {
    Some(match acc {
        Some((prev, prev_reason)) if prev >= next.0 => (prev, prev_reason),
        _ => next,
    })
}

/// Fold the decisions of every `(env NAME …)` capability governing `name`
/// (primary then loaded) strictest-wins, returning the meet decision and the
/// reason of the strictest contributor. `None` means no capability governed
/// `name` (or every governing one evaluated to `Nil`). Folding — rather than
/// taking the first match — keeps a later `(env NAME (deny))` from being
/// silently shadowed by an earlier `(env NAME (ask))` (review W1).
fn fold_env_capabilities(
    config: &Config,
    facts: &ContextFacts,
    name: &str,
    env_scope: Option<EnvScope>,
) -> Option<(Decision, Option<String>)> {
    let mut acc = None;
    for cap in config.security.env_capabilities(name) {
        if let Some(decision) = capability_decision(&cap.decision.value, config, facts, env_scope) {
            acc = meet_decision(acc, decision);
        }
    }
    acc
}

/// Resolve the decision a write-redirect target contributes to the meet,
/// with the reason of the strictest matching capability.
///
/// Folds every redirect-write capability whose pattern matches `target`
/// (strictest wins). With no matching capability the target floors to `:ask`
/// (the default). An expansion-bearing target can never reach `:allow`
/// (asymmetric soundness), so it is raised to at least `:ask` regardless of a
/// matching `allow` — and its reason is dropped so the call site uses the
/// generic redirect reason.
fn resolve_redirect_decision(
    config: &Config,
    facts: &ContextFacts,
    target: &str,
    expansion_bearing: bool,
) -> (Decision, Option<String>) {
    let mut acc = None;
    for cap in config.security.redirect_capabilities() {
        let matches = cap.pattern.as_ref().is_none_or(|pat| pat.is_match(target));
        if !matches {
            continue;
        }
        if let Some(decision) = capability_decision(&cap.decision.value, config, facts, None) {
            acc = meet_decision(acc, decision);
        }
    }
    // A matched capability whose decision evaluated to Nil contributes no
    // release, so it falls back to the default floor.
    let (decision, reason) = acc.unwrap_or((Decision::Ask, None));
    if expansion_bearing && decision < Decision::Ask {
        (Decision::Ask, None)
    } else {
        (decision, reason)
    }
}

/// DisplaySafe for flooring an `:allow` that relied on a match against one or
/// more expansion-bearing words. Names each word (source-faithful,
/// deduplicated) on a single line. Control-escaping is the [`DisplaySafe`] sink's
/// job — this builds the raw text only.
pub(super) fn unresolved_expansion_reason(words: &[String]) -> String {
    let mut names: Vec<String> = words.iter().map(|w| format!("`{w}`")).collect();
    names.sort();
    names.dedup();
    format!(
        "unresolved shell expansion in {} cannot satisfy an allow rule",
        names.join(", ")
    )
}

/// Wrap an embedded-substitution's bubbled reason with an origin clause naming
/// the substitution form and the syntactic position that lexically owns it
/// (carried on the unit as a [`SubstitutionOrigin`], computed at the decompose
/// pass that emitted it).
///
/// The owner is described by kind: `` in `c` `` for a simple-command word,
/// `` in assignment to `v` `` for an assignment value, `` in `for` list ``,
/// `` in `case` subject ``, or `in redirect target`. A dynamic command name
/// (`SimpleCommand(None)`) and a process substitution (`kind == None`) carry no
/// nameable owner and fall back to the generic `(embedded substitution)` form.
///
/// Wraps unconditionally. The sole caller (`eval_units`' `EmbeddedCommand`
/// arm) guarantees this runs at most once per reason by gating on the
/// structural `inner_annotated` flag, never by sniffing the reason text.
/// Single-wrap across nested substitutions is thus an evaluation-structure
/// invariant, and a command name's text can no longer suppress or forge the
/// clause.
fn annotate_embedded_reason(
    inner: &str,
    kind: Option<EmbeddedKind>,
    origin: &SubstitutionOrigin,
) -> String {
    let generic = || format!("{inner} (embedded substitution)");
    let form = match kind {
        Some(EmbeddedKind::Backtick) => "backtick",
        Some(EmbeddedKind::Dollar) => "$(...)",
        // Process substitution carries no named form — keep the generic clause.
        None => return generic(),
    };
    let location = match origin {
        SubstitutionOrigin::SimpleCommand(Some(name)) => {
            format!("in `{name}`")
        }
        // A dynamic command name cannot be named; fall back to generic.
        SubstitutionOrigin::SimpleCommand(None) => return generic(),
        SubstitutionOrigin::Assignment(name) => {
            format!("in assignment to `{name}`")
        }
        SubstitutionOrigin::ForList => "in `for` list".to_string(),
        SubstitutionOrigin::CaseSubject => "in `case` subject".to_string(),
        SubstitutionOrigin::RedirectTarget => "in redirect target".to_string(),
    };
    format!("{inner} ({form} substitution {location})")
}

/// Format the first `Error`-severity diagnostic for the engine's
/// reason field, prefixed with `"parse error: "`. Falls back to the
/// pre-existing generic string when no error-severity entry is
/// present — defensive, since callers only invoke this when
/// `has_errors()` is true.
fn parse_error_reason(diagnostics: &[parser::ParseDiagnostic], input: &str) -> String {
    diagnostics
        .iter()
        .find(|d| d.severity == parser::Severity::Error)
        .map(|d| format!("parse error: {}", d.format_with_source(input)))
        .unwrap_or_else(|| "parse error: ambiguous command boundary".to_string())
}

/// Evaluate a command string against config and context.
///
/// Parses the input, walks the AST to extract all simple commands and embedded
/// substitutions, evaluates each, and returns the aggregate (most restrictive)
/// decision.
pub fn evaluate_command(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
) -> Result<EvalResult, EvalError> {
    let mut fold = PureFold;
    evaluate_command_with_fold(input, config, facts, &mut fold)
}

/// Evaluate a command string with a custom fold for tracing. Uses an empty
/// entry environment; callers that have captured one (the `hook`/`eval`/`check`
/// entrypoints) use [`evaluate_command_with_fold_env`].
pub fn evaluate_command_with_fold<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    evaluate_command_with_fold_env(
        input,
        config,
        facts,
        &EntryEnv::empty(),
        parser::Dialect::Bash,
        fold,
    )
}

/// Evaluate a command string with a custom fold and an explicit entry
/// environment (the names-only exported-environment snapshot). The entry
/// environment is consulted by the env-write floor to decide whether a bare
/// reassignment of an already-exported name reaches a child.
pub fn evaluate_command_with_fold_env<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    entry_env: &EntryEnv,
    dialect: parser::Dialect,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    // The top-level entry discards the origin-annotation flag; only the
    // `EmbeddedCommand` recursion consumes it.
    Ok(eval_units(
        input,
        config,
        facts,
        entry_env,
        dialect,
        fold,
        0,
        None,
        Some(0),
        &std::collections::HashSet::new(),
    )?
    .0)
}

/// The single command-evaluation core: parse `input`, decompose it into
/// `EvalUnit`s, evaluate each, aggregate the strictest decision
/// (`Allow < Ask < Deny`), and floor at `:ask` on an Error-severity parse
/// diagnostic. Both the top-level entry point and the `(authorise …)`
/// recursion path go through here.
///
/// - `depth` is the recursion depth (for the limit guard and per-unit rule
///   evaluation); top-level enters at 0.
/// - `via` pushes a `:via NAME` fact seen by every unit and nested recursion
///   (the `(authorise …)` carrier contract); top-level passes `None`.
/// - `segments` is `Some(outer_offset)` to collect `SegmentDecision`s in
///   outermost coordinates (top-level, for display), or `None` to skip
///   collection (the authorise path, which has no display surface).
///
/// Returns the aggregate [`EvalResult`] together with a boolean meaning *the
/// aggregate reason already carries a substitution-origin clause*. The flag is
/// out-of-band evaluation state: only the `EmbeddedCommand` recursion consumes
/// it (to decide whether to re-annotate), so a command's text can never
/// suppress or forge the annotation. The two other direct callers
/// (`evaluate_command_with_fold`, `evaluate_authorised_string`) discard it.
#[allow(clippy::too_many_arguments)]
fn eval_units<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    entry_env: &EntryEnv,
    dialect: parser::Dialect,
    fold: &mut F,
    depth: usize,
    via: Option<&str>,
    segments: Option<usize>,
    inherited_fns: &std::collections::HashSet<String>,
) -> Result<(EvalResult, bool), EvalError> {
    if depth >= DEFAULT_RECURSION_LIMIT {
        return Ok((
            EvalResult::new(
                Decision::Ask,
                Some(DisplaySafe::new(format!(
                    "recursion depth limit ({DEFAULT_RECURSION_LIMIT}) exceeded"
                ))),
            ),
            false,
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        let reason = DisplaySafe::new("empty command");
        let _out = fold.default_ask(&reason);
        return Ok((EvalResult::new(Decision::Ask, Some(reason)), false));
    }

    // Push the carrier's `:via` fact once, seen by every unit and every
    // nested recursion below this frame.
    let effective_facts = match via {
        Some(name) => {
            let mut f = facts.clone();
            if let Ok(key) = Keyword::new(":via") {
                f.insert_scalar(key, name);
            }
            f
        }
        None => facts.clone(),
    };

    let parse_result = parser::parse_with_dialect(input, dialect);
    let diagnostics = parse_result.diagnostics.clone();
    let has_parse_errors = parse_result.has_errors();
    let tainted_env = config.security.env_capability_names();
    let units = decompose(
        &parse_result.command,
        input,
        &diagnostics,
        &tainted_env,
        inherited_fns,
        entry_env,
    );

    if units.is_empty() {
        let reason = DisplaySafe::new("empty command");
        let _out = fold.default_ask(&reason);
        return Ok((EvalResult::new(Decision::Ask, Some(reason)), false));
    }

    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason: Option<DisplaySafe> = None;
    // Whether `aggregate_reason` already carries a substitution-origin clause.
    // Adopted from whichever unit's reason wins the strictest-wins meet; only
    // an `EmbeddedCommand` unit ever sets it true. Determined structurally, so
    // a command's text cannot flip it.
    let mut aggregate_annotated = false;
    // Lowest-priority reason from internal calls (script-local functions),
    // surfaced only when no decisive unit produced one. See the aggregate
    // loop below.
    let mut internal_call_reason: Option<DisplaySafe> = None;
    let mut segment_decisions: Vec<SegmentDecision> = Vec::new();
    // Spans of structural floors (env prefixes, redirect targets) — they
    // raise overlapping segments to at least `:ask` after the loop, like
    // the parse-error floor, rather than owning segments of their own.
    let mut floor_spans: Vec<super::decompose::Span> = Vec::new();
    // Whether any unit produced a real decision. An argv of nothing but
    // allowlisted env prefixes (`FOO=bar` alone) must not fall through to
    // the initial `:allow`.
    let mut any_decisive_unit = false;

    for unit in &units {
        let unit_span = unit.span();
        // Set true only by the `EmbeddedCommand` arm when its reason carries a
        // substitution-origin clause. Every other unit leaves it false.
        let mut unit_annotated = false;
        let result = match unit {
            EvalUnit::SimpleCommand {
                command,
                args,
                arg_expansions,
                ..
            } => evaluate_at_depth(
                command,
                Argv::new(args, arg_expansions),
                config,
                &effective_facts,
                dialect,
                fold,
                depth,
            )?,
            EvalUnit::EmbeddedCommand {
                source,
                span,
                kind,
                origin,
                inherited_fns,
            } => {
                let (embedded_result, inner_annotated) = eval_units(
                    source,
                    config,
                    &effective_facts,
                    entry_env,
                    dialect,
                    fold,
                    depth + 1,
                    None,
                    segments.map(|base| base + span.0),
                    inherited_fns,
                )?;
                fold.embedded_command(source, embedded_result.decision);
                // Annotate at most once: if the bubbled reason already carries
                // an origin clause (a nested substitution annotated it deeper
                // down), pass it through; otherwise wrap it here. Decided by
                // the structural `inner_annotated` flag, never by reason text.
                let annotated_reason: Option<DisplaySafe> = match &embedded_result.reason {
                    Some(r) if inner_annotated => Some(r.clone()),
                    Some(r) => Some(DisplaySafe::new(annotate_embedded_reason(r, *kind, origin))),
                    None => None,
                };
                unit_annotated = annotated_reason.is_some();
                EvalResult {
                    reason: annotated_reason,
                    ..embedded_result
                }
            }
            EvalUnit::DynamicCommand { reason, .. } => {
                let reason = DisplaySafe::new(reason.clone());
                let _out = fold.default_ask(&reason);
                EvalResult::new(Decision::Ask, Some(reason))
            }
            // A call to a function this command defines is internal: the body
            // was authorised once at its definition, so the call itself runs
            // nothing but dispatch. Resolve to :allow with a traceable reason
            // and never emit `No rule for command …`. As an :allow it never
            // raises the aggregate (Allow is the floor).
            EvalUnit::LocalFunctionCall { name, .. } => {
                fold.local_function_call(name);
                let reason = DisplaySafe::new(format!(
                    "internal call to script-local function `{name}` — body authorised at its definition"
                ));
                EvalResult::new(Decision::Allow, Some(reason))
            }
            // An environment write that reaches a child process (prefix,
            // exported declaration, bare reassignment of an entry-env name, or
            // any write under `set -a`). An unconditional-allow name (the
            // safe-env-vars allowlist) passes through. Otherwise an
            // `(env NAME …)` capability decides: an `allow` releases the floor;
            // an `ask`/`deny` (or a fact/scope-conditional yielding one)
            // contributes that decision. With no capability the write floors to
            // `:ask`, naming the variable. A purely shell-local write never
            // produces this unit.
            EvalUnit::EnvWrite {
                name,
                scope,
                reaches_via_entry_env,
                span,
            } => {
                // The safe-env-vars allowlist contributes an implicit
                // write-allow; every `(env NAME …)` capability contributes
                // its decision. They meet strictest-wins, so a `(deny)` wins
                // over the allowlist and over an earlier `(ask)` (review W1).
                let mut decision = config
                    .security
                    .is_safe_env_var(name)
                    .then_some((Decision::Allow, None));
                if let Some(cap) =
                    fold_env_capabilities(config, &effective_facts, name, Some(*scope))
                {
                    decision = meet_decision(decision, cap);
                }
                match decision {
                    Some((Decision::Allow, _)) => continue,
                    Some((decision, reason)) => {
                        let reason = DisplaySafe::new(reason.unwrap_or_else(|| {
                            format!(
                                "environment write `{name}` is governed by an (env …) capability"
                            )
                        }));
                        if *reaches_via_entry_env {
                            fold.env_entry_contribution(name);
                        }
                        floor_spans.push(*span);
                        let _out = fold.default_ask(&reason);
                        EvalResult::new(decision, Some(reason))
                    }
                    None => {
                        let reason = DisplaySafe::new(format!(
                            "environment write `{name}` reaches a child process and is not in (safe-env-vars …)"
                        ));
                        if *reaches_via_entry_env {
                            fold.env_entry_contribution(name);
                        }
                        floor_spans.push(*span);
                        let _out = fold.default_ask(&reason);
                        EvalResult::new(Decision::Ask, Some(reason))
                    }
                }
            }
            // A write redirection to a non-standard file target. A
            // matching redirect-write capability may lift the floor (an
            // `allow`) or tighten it (`ask`/`deny`); with no match it
            // floors to `:ask`. Plumbing (`/dev/null`, fd dups) and read
            // redirections never reach here.
            EvalUnit::RedirectTarget {
                operator,
                target,
                expansion_bearing,
                span,
            } => {
                let (decision, cap_reason) =
                    resolve_redirect_decision(config, &effective_facts, target, *expansion_bearing);
                if decision == Decision::Allow {
                    continue;
                }
                let reason = DisplaySafe::new(cap_reason.unwrap_or_else(|| {
                    format!("command carries a redirect (`{operator} {target}`)")
                }));
                floor_spans.push(*span);
                let _out = fold.default_ask(&reason);
                EvalResult::new(decision, Some(reason))
            }
            // A tainted env name read into an argv word. The `(env …)`
            // capability's decision resolved against the active facts is
            // contributed; an `allow` (the read-benign default) or a
            // `Nil`-conditional contributes nothing.
            EvalUnit::EnvRead { name, span } => {
                let cap_decision = fold_env_capabilities(config, &effective_facts, name, None);
                match cap_decision {
                    Some((decision, reason)) if decision > Decision::Allow => {
                        let reason = DisplaySafe::new(reason.unwrap_or_else(|| {
                            format!("environment variable `{name}` is read into a command argument")
                        }));
                        floor_spans.push(*span);
                        let _out = fold.default_ask(&reason);
                        EvalResult::new(decision, Some(reason))
                    }
                    _ => continue,
                }
            }
        };
        any_decisive_unit = true;

        // SimpleCommand and DynamicCommand carry their own segment entries
        // (one per unit). EmbeddedCommand units are carriers — they only
        // relay their child segments, otherwise the inner range would appear
        // twice (once as the embed unit, once as the child SimpleCommand).
        // Floor units (EnvWrite, RedirectTarget) share the enclosing
        // command's span; they raise that segment after the loop instead
        // of duplicating its range.
        if let Some(base) = segments {
            if !matches!(
                unit,
                EvalUnit::EmbeddedCommand { .. }
                    | EvalUnit::EnvWrite { .. }
                    | EvalUnit::RedirectTarget { .. }
                    | EvalUnit::EnvRead { .. }
            ) {
                segment_decisions.push(SegmentDecision {
                    start: base + unit_span.0,
                    end: base + unit_span.1,
                    decision: result.decision,
                });
            }
            // Inner segments arrive in outermost coordinates already (offset
            // applied during recursion).
            segment_decisions.extend(result.segment_decisions);
        }

        // An internal call (`:allow`) contributes nothing to the aggregate:
        // it never raises the decision and must not clobber a rule- or
        // floor-derived reason. Its explanation is held as a fallback,
        // surfaced only when no other unit produced a reason (an all-internal
        // command), so the trace and audit record attribute the allow rather
        // than showing an empty reason.
        if matches!(unit, EvalUnit::LocalFunctionCall { .. }) {
            internal_call_reason = internal_call_reason.or(result.reason);
        } else if result.decision >= aggregate_decision {
            aggregate_decision = result.decision;
            aggregate_reason = result.reason;
            aggregate_annotated = unit_annotated;
        }
    }

    // No unit produced a decision (e.g. nothing but allowlisted env
    // prefixes): mirror the empty-units case rather than falling through
    // to the initial `:allow`.
    if !any_decisive_unit && aggregate_decision == Decision::Allow && aggregate_reason.is_none() {
        let reason = DisplaySafe::new("empty command");
        let _out = fold.default_ask(&reason);
        aggregate_decision = Decision::Ask;
        aggregate_reason = Some(reason);
        // `aggregate_annotated` is still its initial `false` here: no unit won
        // the meet, so the only line that sets it true never ran.
    }

    // An all-internal `:allow` (every unit a call to a script-local function)
    // surfaces the internal-call explanation rather than an empty reason.
    if aggregate_decision == Decision::Allow && aggregate_reason.is_none() {
        aggregate_reason = internal_call_reason;
    }

    // Structural floors raise the segments they overlap so display
    // colouring matches the aggregate.
    if let Some(base) = segments {
        for span in &floor_spans {
            let (fs, fe) = (base + span.0, base + span.1);
            for seg in &mut segment_decisions {
                if seg.start < fe && fs < seg.end && seg.decision < Decision::Ask {
                    seg.decision = Decision::Ask;
                }
            }
        }
    }

    // Error-severity parse diagnostics floor the decision at Ask. The same
    // floor applies per-segment so display can colour without re-running the
    // engine — a parse error means each segment's boundary is uncertain.
    if has_parse_errors {
        if aggregate_decision < Decision::Ask {
            aggregate_decision = Decision::Ask;
            aggregate_reason = Some(DisplaySafe::new(parse_error_reason(&diagnostics, input)));
            aggregate_annotated = false;
        }
        for seg in &mut segment_decisions {
            if seg.decision < Decision::Ask {
                seg.decision = Decision::Ask;
            }
        }
    }

    let mut eval_result = EvalResult::new(aggregate_decision, aggregate_reason);
    eval_result.parse_diagnostics = diagnostics;
    eval_result.segment_decisions = segment_decisions;
    Ok((eval_result, aggregate_annotated))
}

/// Evaluate `input` as a full shell command line on behalf of an
/// `(authorise …)`-shaped recursion site.
///
/// Parses `input` with the shell parser, decomposes the AST into
/// evaluation units, and evaluates each unit against `config` and
/// `facts`. The aggregate decision is the strictest across units
/// (`Allow < Ask < Deny`).
///
/// `depth` is the recursion depth at which the inner units are
/// evaluated (callers pass `ctx.recursion_depth + 1`). When `depth`
/// already meets or exceeds `DEFAULT_RECURSION_LIMIT`, the helper
/// returns `:ask` with a recursion-limit reason without parsing.
///
/// When `via_program` is `Some(name)`, the helper pushes `:via name`
/// onto the facts seen by every inner unit. This is the contract that
/// the `via-fact-builtin` spec defines: one push per `(authorise …)`
/// call, not per inner unit. Top-level callers pass `None`.
///
/// `config` is `Option<&Config>` because some `(authorise …)` test
/// fixtures construct an `EvalContext` directly without a `Config`.
/// When `None`, a default `Config` is materialised internally — the
/// inner units evaluate against an empty rule set (yielding `:ask`).
pub(crate) fn evaluate_authorised_string<F: EvalFold>(
    input: &str,
    config: Option<&Config>,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via_program: Option<&str>,
    dialect: parser::Dialect,
) -> Result<EvalResult, EvalError> {
    let default_config = Config::default();
    let effective_config = config.unwrap_or(&default_config);
    // The authorise path takes no segment sink (`None`) — it has no display
    // surface — but otherwise goes through the same core as the top-level
    // path, including `:via` injection, embedded-reason annotation, fold
    // events, and the parse-error floor.
    // The authorise path discards the origin-annotation flag (it has no
    // enclosing substitution to re-annotate for).
    // The authorise recursion re-evaluates a captured command string; it has no
    // separate entry environment, so it uses an empty one. A reaching write in
    // the captured string still floors by its syntax (`export`, prefix); only
    // the bare-reassignment-of-entry-env case is not detected here.
    Ok(eval_units(
        input,
        effective_config,
        facts,
        &EntryEnv::empty(),
        dialect,
        fold,
        depth,
        via_program,
        None,
        &std::collections::HashSet::new(),
    )?
    .0)
}

/// Token-list sibling of [`evaluate_authorised_string`].
///
/// Used when the binding came in as `BindingValue::Tokens(_)` — e.g.
/// `(rest #cmd)`, `(positional #var *|+)`. Unlike the string helper,
/// this one does NOT re-parse argv. The outer shell already decomposed
/// the command line into tokens; joining them with single spaces and
/// re-parsing discards boundary information and exposes shell
/// metacharacters embedded in a single token (e.g. an outer-quoted
/// `-c` argument) as structure at the carrier's frame. That's the
/// policy-bypass the `authorise-token-list-quoting` change closes.
///
/// Semantics:
///
/// - Empty `tokens` → `:ask` with an empty-command reason. Callers
///   normally short-circuit before this via [`BindingValue::is_empty`];
///   the guard preserves the "don't silently mis-recurse" invariant.
/// - Single-element `tokens` → delegate to
///   [`evaluate_authorised_string`] on `tokens[0]`. With one boundary
///   there is no information to lose by re-parsing — the user wrote a
///   single quoted command and expects it to be parsed.
/// - Multi-element `tokens` with `tokens[0]` containing shell
///   metacharacters or empty → `:ask` with a dynamic-or-malformed
///   command-name reason.
/// - Otherwise: push `:via` into facts and evaluate the inner command
///   directly via [`evaluate_at_depth`] with `tokens[0]` as the
///   command and `tokens[1..]` as argv. Each `tokens[i]` arrives at
///   the inner parser as a single argument; the inner program's own
///   parser handles any further structure (e.g. bash's
///   `(parameter "c" #cmd)`).
pub(crate) fn evaluate_authorised_tokens<F: EvalFold>(
    argv: Argv,
    config: Option<&Config>,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via_program: Option<&str>,
    dialect: parser::Dialect,
) -> Result<EvalResult, EvalError> {
    let Argv {
        args: tokens,
        expansions,
    } = argv;
    if depth >= DEFAULT_RECURSION_LIMIT {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(format!(
                "recursion depth limit ({DEFAULT_RECURSION_LIMIT}) exceeded"
            ))),
        ));
    }

    if tokens.is_empty() {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new("empty command")),
        ));
    }

    if tokens.len() == 1 {
        // One token = one outer-shell boundary. No structural
        // information to preserve; re-parsing the lone element as a
        // command line is correct (it's how the user authored it) —
        // unless the token is expansion-bearing, in which case its
        // flattened text is unfaithful to what will run and cannot
        // prove an allow.
        let result = evaluate_authorised_string(
            &tokens[0],
            config,
            facts,
            fold,
            depth,
            via_program,
            dialect,
        )?;
        return Ok(match &expansions[0] {
            Some(display) if result.decision == Decision::Allow => EvalResult::new(
                Decision::Ask,
                Some(DisplaySafe::new(unresolved_expansion_reason(
                    std::slice::from_ref(display),
                ))),
            ),
            _ => result,
        });
    }

    let command = &tokens[0];
    if command.is_empty() || contains_shell_metacharacter(command) {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(format!(
                "dynamic or malformed inner command name: {command:?}"
            ))),
        ));
    }
    // An expansion-bearing command name flattens to a plausible-looking
    // literal (`$X` → `X`); the runtime command is unknown.
    if let Some(display) = &expansions[0] {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(format!(
                "dynamic inner command name: {display}"
            ))),
        ));
    }

    let mut effective_facts = facts.clone();
    if let Some(name) = via_program
        && let Ok(key) = Keyword::new(":via")
    {
        effective_facts.insert_scalar(key, name);
    }

    let default_config = Config::default();
    let effective_config = config.unwrap_or(&default_config);

    evaluate_at_depth(
        command,
        Argv::new(&tokens[1..], &expansions[1..]),
        effective_config,
        &effective_facts,
        dialect,
        fold,
        depth,
    )
}

/// Characters that mark a token as "structurally meaningful in a
/// shell context." When such a character appears in argv[0] of a
/// token-list capture, the outer shell either did not produce that
/// token (the binding consumed an unresolved variable) or the parser
/// upstream is malformed — either way, the recursion has no
/// well-defined inner command name and must `:ask`.
///
/// `=` is included to catch shell assignment-prefix syntax
/// (`FOO=bar cmd`); argv[0] would not normally carry an `=` from a
/// regular outer parse, but if it does, the user almost certainly
/// did not mean to recurse on an environment-prefix as if it were a
/// command name.
pub(crate) fn contains_shell_metacharacter(s: &str) -> bool {
    s.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t'
                | '\n'
                | ';'
                | '|'
                | '&'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '$'
                | '\\'
                | '`'
                | '='
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::ast::{Config, Effect, Spanned};
    use may_i_core::pattern::CommandPattern;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn config_with_rules(rules: Vec<may_i_core::ast::Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn allow_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn allow_rule_with_reason(cmd: &str, reason: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Allow,
                reason: Some(reason.to_string()),
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn deny_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Deny,
                reason: Some(format!("{cmd} denied")),
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn empty_facts() -> ContextFacts {
        ContextFacts::default()
    }

    // -- Simple command --

    #[test]
    fn simple_allowed_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn simple_no_rule_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- Calls to script-local functions (internal calls) --

    #[test]
    fn local_function_call_does_not_ask() {
        // Spec: a call to a defined function resolves to :allow and is never
        // reported as `No rule for command …`.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "materialise() { echo hi; }; materialise foo",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `materialise`"),
            "internal call must not report a missing rule: {reason}"
        );
    }

    #[test]
    fn local_function_body_is_still_authorised() {
        // Spec: the body's dangerous command produces its own decision; the
        // call site contributes no `No rule for command …`.
        let config = config_with_rules(vec![]);
        let result = evaluate_command(
            "cleanup() { rm -rf \"$wt\"; }; cleanup",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("`rm`"),
            "decision should come from the body's rm: {reason}"
        );
        assert!(
            !reason.contains("No rule for command `cleanup`"),
            "the cleanup call must not report a missing rule: {reason}"
        );
    }

    #[test]
    fn local_function_forward_reference_is_internal() {
        // Spec: a body calling a sibling defined later is internal (set-based,
        // order-insensitive).
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "outer() { inner; }; inner() { echo hi; }; outer",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `inner`"),
            "forward-referenced call must be internal: {reason}"
        );
    }

    #[test]
    fn internal_call_does_not_clobber_rule_reason() {
        // A trailing internal call must not overwrite a more informative
        // allow reason from a real rule (it contributes nothing to the
        // aggregate).
        let config = config_with_rules(vec![allow_rule_with_reason("echo", "echo ok")]);
        let result =
            evaluate_command("echo hi; f() { echo bye; }; f", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason.as_deref(), Some("echo ok"));
    }

    #[test]
    fn all_internal_allow_carries_explanatory_reason() {
        // A command that is nothing but internal calls (mutual recursion)
        // resolves to :allow and surfaces the internal-call reason rather
        // than an empty one, so the audit record can attribute the allow.
        let config = config_with_rules(vec![]);
        let result =
            evaluate_command("a() { b; }; b() { a; }; a", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("internal call to script-local function"),
            "all-internal allow should carry an explanatory reason: {reason:?}"
        );
    }

    #[test]
    fn non_defined_unknown_command_still_asks() {
        // Spec: a name not defined as a function is unaffected.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "materialise() { echo hi; }; kubectl get pods",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `kubectl`")
        );
    }

    // -- Substitution-boundary recognition (recognise-local-functions-in-substitutions) --

    #[test]
    fn subst_call_to_live_local_function_allows() {
        // Spec: a live local function inside `$(…)` is internal — :allow, no
        // `No rule for command …`.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "resolve() { echo hi; }; dest=$(resolve)",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `resolve`"),
            "substitution call to a live local function must be internal: {reason}"
        );
    }

    #[test]
    fn subst_forward_reference_still_asks() {
        // Spec: the substitution runs before `resolve` is defined, so it is not
        // live at the site — it stays external and asks.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "dest=$(resolve); resolve() { echo hi; }",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("No rule for command `resolve`"),
            "forward-referenced substitution call must ask: {reason}"
        );
    }

    #[test]
    fn subst_non_defined_command_still_asks() {
        // Spec: an unknown command inside `$(…)` is unaffected by the inherited
        // set.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "resolve() { echo hi; }; dest=$(kubectl get pods)",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("No rule for command `kubectl`"),
            "unknown substitution command must ask: {reason}"
        );
    }

    #[test]
    fn subst_inside_function_body_recognised() {
        // Spec: a substitution inside a function body inherits the Tier-2
        // establishment set, so a call to an established function is internal.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "resolve() { echo hi; }; main() { dest=$(resolve); }; main",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `resolve`"),
            "body-site substitution call must be internal: {reason}"
        );
    }

    #[test]
    fn subst_nested_recognised() {
        // Spec: recognition propagates through nested substitutions — both `f`
        // and `g` in `out=$(f $(g))` are internal.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "g() { echo x; }; f() { echo y; }; out=$(f $(g))",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `f`")
                && !reason.contains("No rule for command `g`"),
            "nested substitution calls must both be internal: {reason}"
        );
    }

    #[test]
    fn subst_nested_forward_reference_not_recognised() {
        // A function defined after the substitution is not live at the nested
        // site, so it still asks even though the outer call is internal.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "f() { echo y; }; out=$(f $(g)); g() { echo x; }",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("No rule for command `g`"),
            "nested forward-referenced call must ask: {reason}"
        );
    }

    #[test]
    fn subst_in_parameter_expansion_default_recognised() {
        // A substitution inside a `${x:-$(resolve)}` operand inherits the same
        // site liveness as an inline `$(resolve)` would.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            "resolve() { echo hi; }; dest=${x:-$(resolve)}",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains("No rule for command `resolve`"),
            "param-expansion-default substitution call must be internal: {reason}"
        );
    }

    #[test]
    fn subst_inherited_fn_unset_within_scope_is_not_recognised() {
        // Soundness: `fn` is inherited into the substitution, but the
        // substitution's own source `unset -f fn` before reaching the body-site
        // call `$(fn)`. In real bash the subshell's `fn` is gone, so `$(fn)`
        // runs an EXTERNAL `fn` — it must ask, matching the bare call at that
        // site (whose Tier-2 establishment set excludes the unset name). The
        // carried set must not re-add an inherited name the site excluded.
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("unset")]);
        let script = "fn() { echo hi; }; x=$( unset -f fn; g() { out=$(fn); }; g )";
        let result = evaluate_command(script, &config, &empty_facts()).unwrap();
        assert_eq!(
            result.decision,
            Decision::Ask,
            "fn is unset before the body substitution runs"
        );
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("No rule for command `fn`"),
            "unset inherited fn must ask in body substitution: {reason}"
        );
    }

    #[test]
    fn subst_recognised_function_dangerous_body_still_asks() {
        // Spec/D5: recognising the call as internal does not suppress the body's
        // own gate — the body's `rm` produces the ask, and the `wipe` call adds
        // no `No rule for command …`.
        let config = config_with_rules(vec![]);
        let result = evaluate_command(
            "wipe() { rm -rf \"$d\"; }; x=$(wipe)",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("`rm`"),
            "decision should come from the body's rm: {reason}"
        );
        assert!(
            !reason.contains("No rule for command `wipe`"),
            "the wipe substitution call must not report a missing rule: {reason}"
        );
    }

    // -- Liveness: closed bypasses (D2) --

    #[test]
    fn top_level_call_before_definition_is_external() {
        // `rm` is called before it is defined; the external rm runs, so the
        // call must ask — not resolve internal.
        let config = config_with_rules(vec![allow_rule("true")]);
        let result =
            evaluate_command("rm -rf /tmp/x; rm() { true; }", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.reason.as_deref(), Some("No rule for command `rm`"));
    }

    #[test]
    fn call_after_unset_f_is_external() {
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("unset")]);
        let result = evaluate_command(
            "rm() { true; }; unset -f rm; rm -rf /tmp/x",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.reason.as_deref(), Some("No rule for command `rm`"));
    }

    #[test]
    fn body_forward_reference_invoked_before_definition_is_external() {
        // `g` is invoked before `f` is defined, so the body's `f` runs the
        // external f. Only the top-level `g` call is internal.
        let config = config_with_rules(vec![allow_rule("true")]);
        let result =
            evaluate_command("g() { f; }; g; f() { true; }", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.reason.as_deref(), Some("No rule for command `f`"));
    }

    // -- Compound commands --

    #[test]
    fn compound_and_most_restrictive() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello && rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn compound_deny_wins() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo hello; rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn compound_all_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("cat")]);
        let result = evaluate_command("echo a && echo b | cat", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Embedded commands --

    #[test]
    fn embedded_command_denied() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm -rf /)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn embedded_command_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("date")]);
        let result = evaluate_command("echo $(date)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn nested_embedded_command() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(echo $(rm -rf /))", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Embedded-substitution origin annotation --

    #[test]
    fn embedded_dollar_substitution_names_outer_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(r#"echo "$(:rebuild)""#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `:rebuild` ($(...) substitution in `echo`)")
        );
    }

    #[test]
    fn embedded_backtick_substitution_names_outer_command() {
        let config = config_with_rules(vec![allow_rule("grep")]);
        let result =
            evaluate_command(r#"grep -nE "x|`:rebuild`y" file"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `:rebuild` (backtick substitution in `grep`)")
        );
    }

    #[test]
    fn command_name_with_annotation_phrase_does_not_suppress_clause() {
        // The inner command name is the literal text `a substitution in b`
        // (single-quoted, no rule matches it). A text-sniffing idempotency
        // guard would see ` substitution in ` in the bubbled reason and
        // suppress the enclosing substitution's origin clause — exactly the
        // adversary-controllable degradation this change removes. The clause
        // naming `echo` MUST survive.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(
            r#"echo "$('a substitution in b')""#,
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `a substitution in b` ($(...) substitution in `echo`)")
        );
    }

    #[test]
    fn top_level_no_rule_reason_is_not_annotated() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("kubectl get pods", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert_eq!(reason, "No rule for command `kubectl`");
        assert!(
            !reason.contains("substitution in"),
            "top-level reason must not be annotated: {reason}"
        );
    }

    #[test]
    fn nested_embedded_substitution_does_not_double_wrap() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("grep")]);
        let result = evaluate_command(
            r#"echo "$(grep -nE `:rebuild` file)""#,
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        let count = reason.matches(" substitution in ").count();
        assert_eq!(
            count, 1,
            "expected exactly one ` substitution in ` clause, got {count}: {reason}"
        );
    }

    #[test]
    fn nested_process_substitution_does_not_double_wrap() {
        // A process substitution (kind `None`) always takes the generic
        // `(embedded substitution)` clause. When it bubbles through an
        // enclosing substitution the structural `inner_annotated` flag must
        // suppress re-wrapping — no `… (embedded substitution) ($(...)
        // substitution in `echo`)` and no doubled generic clause.
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("cat")]);
        let result =
            evaluate_command(r#"echo "$(cat <(badcmd))""#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert_eq!(
            reason.matches("(embedded substitution)").count(),
            1,
            "expected exactly one generic clause: {reason}"
        );
        assert!(
            !reason.contains(" substitution in "),
            "generic clause must not gain a named owner from the outer layer: {reason}"
        );
    }

    // -- Substitution-origin attribution (per syntactic owner) --

    #[test]
    fn annotate_embedded_reason_per_origin() {
        use super::super::decompose::SubstitutionOrigin::*;
        let dollar =
            |o| annotate_embedded_reason("No rule for command `x`", Some(EmbeddedKind::Dollar), &o);
        assert_eq!(
            dollar(SimpleCommand(Some("grep".into()))),
            "No rule for command `x` ($(...) substitution in `grep`)"
        );
        assert_eq!(
            dollar(Assignment("dest".into())),
            "No rule for command `x` ($(...) substitution in assignment to `dest`)"
        );
        assert_eq!(
            dollar(ForList),
            "No rule for command `x` ($(...) substitution in `for` list)"
        );
        assert_eq!(
            dollar(CaseSubject),
            "No rule for command `x` ($(...) substitution in `case` subject)"
        );
        assert_eq!(
            dollar(RedirectTarget),
            "No rule for command `x` ($(...) substitution in redirect target)"
        );
        // A dynamic command name has no nameable owner → generic fallback.
        assert_eq!(
            dollar(SimpleCommand(None)),
            "No rule for command `x` (embedded substitution)"
        );
        // Backtick form keeps the per-owner clause.
        assert_eq!(
            annotate_embedded_reason(
                "No rule for command `x`",
                Some(EmbeddedKind::Backtick),
                &Assignment("v".into())
            ),
            "No rule for command `x` (backtick substitution in assignment to `v`)"
        );
        // Process substitution (kind None) is never named, regardless of owner.
        assert_eq!(
            annotate_embedded_reason("No rule for command `x`", None, &RedirectTarget),
            "No rule for command `x` (embedded substitution)"
        );
        // Single-wrap across nesting is no longer this function's concern (it
        // wraps unconditionally); the `EmbeddedCommand` arm's structural flag
        // owns idempotency. See `nested_embedded_substitution_does_not_double_wrap`
        // and `nested_process_substitution_does_not_double_wrap`.
    }

    #[test]
    fn motivating_substitution_origin_names_assignment_not_set() {
        // Regression for the cross-attribution bug: the substitution lives in
        // the assignment to `dest` inside `main`'s body, not in the unrelated
        // leading `set`.
        let config = config_with_rules(vec![]);
        let result = evaluate_command(
            "set -euo pipefail; main() { dest=$(resolve); }; main",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("assignment to `dest`"),
            "reason should name the assignment to `dest`: {reason}"
        );
        assert!(
            !reason.contains("in `set`"),
            "reason must not attribute the substitution to `set`: {reason}"
        );
    }

    #[test]
    fn substitution_in_assignment_names_assignment_target() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("dest=$(badcmd)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `badcmd` ($(...) substitution in assignment to `dest`)")
        );
    }

    #[test]
    fn substitution_in_simple_command_names_that_command() {
        let config = config_with_rules(vec![allow_rule("grep")]);
        let result = evaluate_command(r#"grep "$(badcmd)" file"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `badcmd` ($(...) substitution in `grep`)")
        );
    }

    #[test]
    fn substitution_in_redirect_target_describes_the_redirect() {
        // `badcmd` is denied so the substitution's annotated reason wins over
        // the redirect-write floor (`:ask`), surfacing the per-owner clause.
        let config = config_with_rules(vec![allow_rule("cat"), deny_rule("badcmd")]);
        let result = evaluate_command(r#"cat > "$(badcmd)""#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("substitution in redirect target"),
            "reason should describe the redirect target: {reason}"
        );
        assert!(
            !reason.contains("`cat`"),
            "reason must not attribute the substitution to `cat`: {reason}"
        );
    }

    #[test]
    fn substitution_in_redirect_target_no_rule_does_not_cross_attribute() {
        // The literal spec scenario: `cat > "$(badcmd)"` with no rule for
        // badcmd. The redirect-write floor dominates, but its reason still
        // describes the redirect target and names no unrelated command.
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate_command(r#"cat > "$(badcmd)""#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("redirect"),
            "reason should describe the redirect target: {reason}"
        );
    }

    #[test]
    fn embedded_substitution_with_dynamic_outer_falls_back_to_generic() {
        let config = config_with_rules(vec![]);
        // Outer first word is `$(which python)` — dynamic — so the
        // annotation cannot name an outer command and falls back to
        // the generic "embedded substitution" form. `which` itself has
        // no rule, so the embedded path bubbles up.
        let result =
            evaluate_command("$(which python) --version", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("(embedded substitution)"),
            "reason should fall back to generic embedded substitution clause: {reason}"
        );
    }

    // -- Pipeline negation (`!`) --

    #[test]
    fn negated_pipeline_evaluates_inner_command() {
        let config = config_with_rules(vec![deny_rule("kill")]);
        let result = evaluate_command("! kill -0 %1", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(reason.contains("kill"), "reason should name kill: {reason}");
        assert!(!reason.contains('!'), "reason must not name `!`: {reason}");
    }

    #[test]
    fn negation_does_not_change_decision() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let negated = evaluate_command("! rm -rf /", &config, &empty_facts()).unwrap();
        let plain = evaluate_command("rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(negated.decision, Decision::Deny);
        assert_eq!(negated.decision, plain.decision);
    }

    #[test]
    fn negated_command_with_no_rule_names_real_command() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("! kubectl get pods", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No rule for command `kubectl`")
        );
    }

    #[test]
    fn bang_as_argument_is_literal_in_argv() {
        use may_i_core::pattern::{ArgPattern, Expr};
        // `find` denied when `!` appears anywhere in argv. The deny proves
        // `!` reached `find`'s argv rather than being read as negation.
        let rule = may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "find".to_string(),
            ))),
            effect: spanned(Effect::And {
                effects: vec![
                    spanned(Effect::ArgPattern(ArgPattern::Anywhere(vec![
                        Expr::Literal("!".to_string()),
                    ]))),
                    spanned(Effect::Terminal {
                        decision: Decision::Deny,
                        reason: Some("find with ! arg".to_string()),
                    }),
                ],
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate_command("find . ! -name foo", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Dynamic command names --

    #[test]
    fn dynamic_command_name_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("$EDITOR file.txt", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("dynamic"));
    }

    // -- Empty input --

    #[test]
    fn empty_string_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("empty"));
    }

    #[test]
    fn whitespace_only_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("   ", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- If/for/case --

    #[test]
    fn if_then_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result =
            evaluate_command("if true; then rm -rf /; fi", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn or_evaluates_both_sides() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_command("false || rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn case_arm_deny() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command(
            "case $x in a) rm -rf /;; b) echo hi;; esac",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Control characters in command names --

    /// `$'\n'` ANSI-C quoting (and unterminated forms like `$'\n`) can
    /// yield a parsed command name containing a literal newline. The
    /// reason field is consumed as a single JSON string by the Claude
    /// Code hook surface; control chars must be escaped.
    #[test]
    fn control_chars_in_command_name_are_escaped_in_reason() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("$'\\n", &config, &empty_facts()).unwrap();
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains('\n'),
            "reason must not contain literal newline: {reason:?}"
        );
    }

    /// A *dynamic* command name (a command substitution in command position)
    /// is named in its reason via `dynamic_parts()`, a separate interpolation
    /// path from the static-name one. A raw control byte in that source must
    /// be escaped too — the spec requires every input-derived name be
    /// control-escaped, not only the simple-command path.
    #[test]
    fn control_char_in_dynamic_command_name_is_escaped_in_reason() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // A parameter expansion in command position is a dynamic command name;
        // a raw control byte in its operand source flows through
        // `dynamic_parts()` into the reason and must be escaped.
        let result = evaluate_command("${x-\u{1b}foo}", &config, &empty_facts()).unwrap();
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.chars().any(|c| c.is_control()),
            "dynamic-command reason must carry no raw control char: {reason:?}"
        );
    }

    /// Terminated `$'\n'` inside a substitution decodes to a real newline in
    /// the inner command name, which is then interpolated into the bubbled,
    /// origin-annotated reason. The escape on that path must hold so the
    /// reason stays single-line. Complements the unterminated-`$'\n` case
    /// above and pins the substitution-interpolated-name variant.
    #[test]
    fn newline_command_name_in_substitution_is_escaped_in_reason() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command(r#"echo "$($'\n'x)""#, &config, &empty_facts()).unwrap();
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            !reason.contains('\n'),
            "reason must contain no raw newline: {reason:?}"
        );
    }

    // -- POSIX line continuation regression (2026-05-18 incident) --

    #[test]
    fn line_continuation_reports_real_command_name() {
        let config = config_with_rules(vec![allow_rule("mkdir"), allow_rule("ls")]);
        // Input ends in `&& \<NL>   ls bar` — the lexer used to emit a
        // phantom `\n` first word for the continuation segment, so the
        // engine reported `No rule for command `\n``.
        let result =
            evaluate_command("mkdir -p foo && \\\n   ls bar", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        if let Some(reason) = result.reason.as_deref() {
            assert!(
                !reason.contains("`\n`"),
                "reason still references phantom newline command: {reason}"
            );
        }
    }

    #[test]
    fn line_continuation_unknown_command_names_real_command() {
        let config = config_with_rules(vec![allow_rule("mkdir")]);
        let result =
            evaluate_command("mkdir -p foo && \\\n   ls bar", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("`ls`"),
            "expected reason to name `ls`, got: {reason}"
        );
    }

    // -- Process substitution --

    #[test]
    fn process_substitution_both_allowed() {
        let config = config_with_rules(vec![allow_rule("diff"), allow_rule("ls")]);
        let result = evaluate_command("diff <(ls /a) <(ls /b)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn process_substitution_argument_inner_command_evaluated() {
        let config = config_with_rules(vec![allow_rule("cat"), deny_rule("rm")]);
        let result = evaluate_command("cat <(rm -rf /danger)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn process_substitution_redirect_target_inner_command_evaluated() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_command(
            "while read x; do :; done < <(rm -rf /danger)",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn process_substitution_redirect_does_not_drop_trailing_command() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_command(
            "f() { while read x; do :; done < <(find .); rm -rf /danger; }",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn output_process_substitution_inner_command_evaluated() {
        let config = config_with_rules(vec![allow_rule("tee"), deny_rule("rm")]);
        let result = evaluate_command("tee >(rm x)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn unplaceable_procsub_input_floors_to_ask_without_dropping_tokens() {
        // A stray `)` after a process substitution cannot be placed in the
        // grammar. The backstop (D3): an Error-severity diagnostic is emitted
        // and floors the decision to :ask, even though every named command is
        // allowed — rather than silently dropping the unplaceable token.
        let config = config_with_rules(vec![allow_rule("cat"), allow_rule("echo")]);
        let result = evaluate_command("cat <(echo hi) )", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .parse_diagnostics
                .iter()
                .any(|d| d.severity == may_i_shell_parser::Severity::Error),
            "expected an Error-severity diagnostic, got: {:?}",
            result.parse_diagnostics
        );
    }

    // -- Recursion depth limit --

    // -- Parse diagnostics --

    #[test]
    fn parse_error_reason_names_diagnostic_kind_and_location() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated single quote — Error severity. DisplaySafe should
        // name the diagnostic and a line position.
        let result = evaluate_command("echo 'unterminated", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.starts_with("parse error: unterminated single quote at line "),
            "reason: {reason}"
        );
    }

    #[test]
    fn parse_error_reason_via_authorised_string() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let mut fold = PureFold;
        let result = evaluate_authorised_string(
            "echo 'unterminated",
            Some(&config),
            &empty_facts(),
            &mut fold,
            1,
            Some("bash"),
            may_i_shell_parser::Dialect::Bash,
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.starts_with("parse error: unterminated single quote at line "),
            "reason: {reason}"
        );
    }

    #[test]
    fn parse_error_reason_describes_first_diagnostic_only() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Input that produces multiple Error-severity diagnostics from
        // a single root cause (unterminated `$(` body cascades into an
        // unterminated `"`).
        // Both `echo`s are allowed so the rule-side aggregate stays at
        // `:allow`; the parse-error floor raises it to `:ask` and the
        // reason is the formatted first diagnostic.
        let result = evaluate_command(r#"echo "foo $(echo"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let errors = result
            .parse_diagnostics
            .iter()
            .filter(|d| d.severity == may_i_shell_parser::Severity::Error)
            .count();
        assert!(
            errors >= 2,
            "expected >= 2 error diagnostics, got {errors}: {:?}",
            result.parse_diagnostics
        );
        let reason = result.reason.as_deref().unwrap_or("");
        let first = result
            .parse_diagnostics
            .iter()
            .find(|d| d.severity == may_i_shell_parser::Severity::Error)
            .unwrap();
        let expected_prefix = format!("parse error: {}", first.message());
        assert!(
            reason.starts_with(&expected_prefix),
            "reason `{reason}` does not start with `{expected_prefix}`"
        );
    }

    #[test]
    fn parse_error_floors_allowed_at_ask() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated double quote — Error severity. This is the
        // exact input from spec scenario "Allowed command with parse
        // error": pin the reason shape (kind + 1-based line/col).
        let result = evaluate_command(r#"echo "hello; rm -rf /"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(!result.parse_diagnostics.is_empty());
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.starts_with("parse error: unterminated double quote"),
            "reason: {reason}"
        );
        assert!(reason.contains("line 1, column 6"), "reason: {reason}");
    }

    #[test]
    fn parse_error_does_not_downgrade_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        // Unterminated quote + denied command — deny > ask
        let result = evaluate_command(r#"rm "unterminated"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Unterminated substitution is not recursed into --

    #[test]
    fn unterminated_command_substitution_not_recursed() {
        let config = config_with_rules(vec![allow_rule("grep")]);
        let result = evaluate_command(r#"grep -n "x$(y" file"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_deref().unwrap_or("");
        assert!(
            reason.starts_with("parse error: unterminated command substitution"),
            "reason: {reason}"
        );
        assert!(
            !reason.contains("No rule for command"),
            "reason must not fabricate a command from swallowed text: {reason}"
        );
    }

    #[test]
    fn well_formed_substitution_still_recurses() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm -rf /)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    /// Open Question (2.5): unterminated `${…}` / `$((…))` never produce an
    /// embedded *command* unit (only `$( … )` / `` ` … ` `` / `<( … )` do),
    /// so the suppression in `decompose` is a no-op for them. They still
    /// floor to `:ask` with a `parse error: …` reason and never fabricate a
    /// `No rule for command …` clause from the swallowed tail.
    #[test]
    fn unterminated_parameter_and_arithmetic_floor_without_fabrication() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        for input in [r#"echo ${x"#, r#"echo $((1+"#] {
            let result = evaluate_command(input, &config, &empty_facts()).unwrap();
            assert_eq!(result.decision, Decision::Ask, "input: {input}");
            let reason = result.reason.as_deref().unwrap_or("");
            assert!(
                reason.starts_with("parse error: "),
                "input {input}: reason: {reason}"
            );
            assert!(
                !reason.contains("No rule for command"),
                "input {input}: reason: {reason}"
            );
        }
    }

    #[test]
    fn parse_warning_does_not_floor() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("true")]);
        // Missing fi — Warning severity
        let result = evaluate_command("if true; then echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.parse_diagnostics.is_empty());
    }

    #[test]
    fn well_formed_has_no_diagnostics() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert!(result.parse_diagnostics.is_empty());
    }

    #[test]
    fn rule_sees_keyword_spelled_argument() {
        use may_i_core::pattern::{ArgPattern, Expr};
        // `rm` is denied when `done` appears anywhere in its arguments. If the
        // lexer dropped `done` (the old reserved-word bug) the rule would not
        // match and the decision would fall through to Ask. The deny proves
        // the engine evaluated the full `rm -rf done` argv.
        let rule = may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "rm".to_string(),
            ))),
            effect: spanned(Effect::And {
                effects: vec![
                    spanned(Effect::ArgPattern(ArgPattern::Anywhere(vec![
                        Expr::Literal("done".to_string()),
                    ]))),
                    spanned(Effect::Terminal {
                        decision: Decision::Deny,
                        reason: Some("rm with done argument".to_string()),
                    }),
                ],
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };
        let config = config_with_rules(vec![rule]);

        // `done` is a trailing argument — the rule matches and denies.
        let result = evaluate_command("rm -rf done", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.parse_diagnostics.is_empty());

        // Without `done`, the arg pattern fails and the rule does not apply.
        let result = evaluate_command("rm -rf /tmp", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn recursion_depth_limit() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("rm")]);
        // Create deeply nested: $(echo $(echo $(echo ...$(rm /)...)))
        let mut input = "rm /".to_string();
        for _ in 0..15 {
            input = format!("echo $({input})");
        }
        let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
        // Should hit depth limit and return Ask
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("depth"));
    }

    #[test]
    fn authorised_string_depth_limit_at_boundary() {
        // `evaluate_authorised_string` MUST short-circuit when its
        // `depth` argument already meets the limit — every
        // `(authorise …)` recursion adds one step.
        let config = config_with_rules(vec![allow_rule("echo")]);
        let mut fold = PureFold;
        let result = evaluate_authorised_string(
            "echo hi",
            Some(&config),
            &empty_facts(),
            &mut fold,
            DEFAULT_RECURSION_LIMIT,
            Some("bash"),
            may_i_shell_parser::Dialect::Bash,
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("depth"));
    }

    #[test]
    fn authorised_string_pushes_via_for_every_unit() {
        use may_i_core::ast::{FactQuery, Predicate, Provenance};
        use may_i_core::predicates::FactPattern;
        use may_i_core::span::Span;

        // Rule: echo with (when (fact? [:via "bash"]) (deny "via"))
        let echo_via_deny = may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                "echo".into(),
            ))),
            effect: spanned(Effect::When {
                predicate: spanned(Predicate::Fact(FactQuery::Value {
                    key: may_i_core::Keyword::new(":via").unwrap(),
                    pattern: FactPattern::Literal("bash".to_string()),
                })),
                effect: Box::new(spanned(Effect::Terminal {
                    decision: Decision::Deny,
                    reason: Some("via".to_string()),
                })),
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: Provenance::PrimaryConfig,
        };
        let config = config_with_rules(vec![echo_via_deny]);
        let mut fold = PureFold;
        let result = evaluate_authorised_string(
            "echo a && echo b",
            Some(&config),
            &empty_facts(),
            &mut fold,
            1,
            Some("bash"),
            may_i_shell_parser::Dialect::Bash,
        )
        .unwrap();
        // Both inner echo units see :via "bash" — both deny — aggregate denies.
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- segment_decisions: spec scenarios --

    #[test]
    fn segment_decisions_single_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hi", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.segment_decisions.len(), 1);
        let s = &result.segment_decisions[0];
        assert_eq!((s.start, s.end, s.decision), (0, 7, Decision::Allow));
    }

    #[test]
    fn segment_decisions_compound_and() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo a && rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        let entries: Vec<_> = result
            .segment_decisions
            .iter()
            .map(|s| (s.start, s.end, s.decision))
            .collect();
        assert_eq!(
            entries,
            vec![(0, 6, Decision::Allow), (10, 18, Decision::Ask)]
        );
    }

    #[test]
    fn segment_decisions_embedded_substitution_present() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        // Outer simple command echo at 0..10 (Allow on its own).
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|s| s.start == 0 && s.end == 10 && s.decision == Decision::Allow)
        );
        // Inner rm covers the substitution body 7..9.
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|s| s.start == 7 && s.end == 9 && s.decision == Decision::Deny)
        );
    }

    #[test]
    fn segment_decisions_dynamic_command_is_ask() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("$EDITOR file.txt", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.segment_decisions.len(), 1);
        let s = &result.segment_decisions[0];
        assert_eq!(s.decision, Decision::Ask);
        assert_eq!(s.start, 0);
        assert_eq!(s.end, 16);
    }

    #[test]
    fn segment_decisions_empty_input_is_empty() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("", &config, &empty_facts()).unwrap();
        assert!(result.segment_decisions.is_empty());
    }

    #[test]
    fn segment_decisions_whitespace_input_is_empty() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("   ", &config, &empty_facts()).unwrap();
        assert!(result.segment_decisions.is_empty());
    }

    #[test]
    fn segment_decisions_nested_embed_contained_in_parent() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(echo $(rm))", &config, &empty_facts()).unwrap();
        // Locate the deny entry — must be contained in some other entry.
        let deny = result
            .segment_decisions
            .iter()
            .find(|s| s.decision == Decision::Deny)
            .expect("deny entry");
        assert!(
            result
                .segment_decisions
                .iter()
                .any(|other| !std::ptr::eq(other, deny)
                    && other.start <= deny.start
                    && other.end >= deny.end
                    && (other.start < deny.start || other.end > deny.end)),
            "deny entry {:?} should be contained in some larger entry. all: {:?}",
            deny,
            result.segment_decisions
        );
    }

    #[test]
    fn segment_decisions_parse_error_floors_segment() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated double quote — Error severity floors aggregate to Ask
        // and per-segment Allow → Ask, so display can colour without
        // re-running the engine.
        let result = evaluate_command(r#"echo "hello"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .segment_decisions
                .iter()
                .all(|s| s.decision >= Decision::Ask)
        );
    }

    // -- segment_decisions: property tests --

    use proptest::prelude::*;

    /// Regression: an unclosed `>(` / `<(` / `$(` substitution must produce
    /// nested (not overlapping) segment spans. Previously
    /// `find_substitution_spans` skipped the unclosed opener and re-scanned
    /// inside the body, so the parser-extracted source paired with the wrong
    /// (smaller) span and the recursion produced segments extending past the
    /// outer span.
    #[test]
    fn unclosed_process_substitution_segments_nest() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let input = "\"\">(<(\"\")";
        let result = evaluate_command(input, &config, &empty_facts()).unwrap();
        for s in &result.segment_decisions {
            assert!(
                s.end <= input.len(),
                "segment {s:?} extends past input length {}",
                input.len()
            );
        }
        let mut top = top_level(&result.segment_decisions);
        top.sort_by_key(|s| s.start);
        for pair in top.windows(2) {
            assert!(
                pair[0].end <= pair[1].start,
                "top-level segments overlap: {:?} and {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    fn arb_input() -> impl Strategy<Value = String> {
        crate::eval::tests::arb_shell_chars()
    }

    /// Inputs that provably drive a control character into a command-name
    /// position, so `prop_reason_is_single_line` actually exercises the
    /// `DisplaySafe` escaping sink on the reason-interpolated-name path rather than
    /// passing vacuously. Mixes raw non-separator control bytes (`\x00`,
    /// `\x1b`, …) and ANSI-C source forms (`$'\n'`, `$'\t'`), placed at top
    /// level and inside a substitution, with ordinary shell soup as a control
    /// arm.
    fn arb_reason_input() -> impl Strategy<Value = String> {
        // Raw control bytes that are NOT shell word separators, so they land
        // inside the command-name token rather than splitting it.
        let raw_ctrl = prop::sample::select(vec!['\u{0}', '\u{1}', '\u{7}', '\u{8}', '\u{1b}']);
        // ANSI-C quoting forms that decode to a control char *within* a word —
        // the only way a newline/tab reaches a name instead of separating it.
        let ansi_c = prop::sample::select(vec![r"$'\n'", r"$'\t'", r"$'\r'", r"$'\x1b'"]);
        let template = prop::sample::select(vec![
            "{x}cmd", // control char opens a top-level command name
            "{x}cmd arg",
            r#"echo "$({x}cmd)""#, // …inside a $() substitution's name
            "dest=$({x}cmd)",      // …inside an assignment's substitution
            "cat <({x}cmd)",       // …inside a process substitution's name
            "`{x}cmd`",            // …in a backtick command-sub *as* the command name (dynamic)
            "$({x}cmd) z",         // …in a $() command-sub as the command name (dynamic)
            "${v-{x}foo}",         // …in a parameter-expansion operand (dynamic command name)
        ]);
        prop_oneof![
            (raw_ctrl, template.clone()).prop_map(|(c, t)| t.replace("{x}", &c.to_string())),
            (ansi_c, template).prop_map(|(s, t)| t.replace("{x}", s)),
            crate::eval::tests::arb_shell_chars(),
        ]
    }

    /// Well-formed shell pipelines built from a fixed command/arg/operator
    /// vocabulary. Used to property-test that a leading `!` is transparent:
    /// these never carry parse errors, so reasons (which embed line/column
    /// for parse errors) are stable under the 2-byte `! ` prefix shift.
    fn arb_pipeline() -> impl Strategy<Value = String> {
        let segment = (
            prop::sample::select(vec!["echo", "rm", "cat", "ls"]),
            prop::collection::vec(prop::sample::select(vec!["a", "-rf", "foo", "/tmp"]), 0..3),
        )
            .prop_map(|(cmd, args)| {
                let mut s = cmd.to_string();
                for a in args {
                    s.push(' ');
                    s.push_str(a);
                }
                s
            });
        (
            segment.clone(),
            prop::collection::vec(
                (
                    prop::sample::select(vec![" | ", " && ", " || ", " ; "]),
                    segment,
                ),
                0..3,
            ),
        )
            .prop_map(|(first, rest)| {
                let mut s = first;
                for (op, seg) in rest {
                    s.push_str(op);
                    s.push_str(&seg);
                }
                s
            })
    }

    fn top_level(decisions: &[crate::SegmentDecision]) -> Vec<&crate::SegmentDecision> {
        decisions
            .iter()
            .filter(|s| {
                !decisions.iter().any(|other| {
                    !std::ptr::eq(other, *s)
                        && other.start <= s.start
                        && other.end >= s.end
                        && (other.start < s.start || other.end > s.end)
                })
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 64, .. ProptestConfig::default() })]

        /// D4 metamorphic invariant (`recognise-local-functions-in-substitutions`):
        /// a function call inside `x=$(call)` at a site receives the same
        /// internal/external classification as the bare `call` at that site.
        /// The bare-call path — already specified and tested — is ground truth.
        /// Up to three function definitions and a call placed at a random slot
        /// among them exercise live / forward-reference / undefined cases;
        /// bodies use only the allowlisted `echo`, so the sole decision driver
        /// is the call's own classification (Allow iff internal, else Ask).
        #[test]
        fn prop_subst_classification_equals_bare_call(
            defined in prop::collection::vec(any::<bool>(), 3),
            target in 0usize..3,
            slot in 0usize..=3,
        ) {
            let config = config_with_rules(vec![allow_rule("echo")]);
            let defs: Vec<String> = defined
                .iter()
                .enumerate()
                .filter(|&(_, &d)| d)
                .map(|(i, _)| format!("f{i}() {{ echo hi; }}"))
                .collect();
            let call = format!("f{target}");
            let at = slot.min(defs.len());
            let build = |call_text: &str| {
                let mut stmts = defs.clone();
                stmts.insert(at, call_text.to_string());
                stmts.join("; ")
            };
            let bare = build(&call);
            let bare_d = evaluate_command(&bare, &config, &empty_facts()).unwrap().decision;
            // Each substitution surface form must classify the call identically
            // to the bare call at the same site (D4) — inline `$(…)`, a
            // parameter-expansion operand, and an `Index` array subscript are
            // all positions the emitter and the liveness walk must agree on.
            for wrapped in [
                build(&format!("x=$({call})")),
                build(&format!("dest=${{y:-$({call})}}")),
                build(&format!("dest=${{arr[$({call})]}}")),
            ] {
                let wrapped_d = evaluate_command(&wrapped, &config, &empty_facts())
                    .unwrap()
                    .decision;
                prop_assert_eq!(bare_d, wrapped_d, "bare {:?} vs subst {:?}", bare, wrapped);
            }
        }

        /// `harden-shell-parse-fidelity`: a leading `!` is pipeline negation —
        /// authorisation-transparent. For any well-formed pipeline `P`,
        /// `! P` yields the same decision and the same reason (command-name
        /// resolution) as `P`.
        #[test]
        fn prop_leading_negation_is_transparent(p in arb_pipeline()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let plain = evaluate_command(&p, &config, &empty_facts()).unwrap();
            let negated = evaluate_command(&format!("! {p}"), &config, &empty_facts()).unwrap();
            prop_assert_eq!(plain.decision, negated.decision);
            prop_assert_eq!(plain.reason, negated.reason);
        }

        #[test]
        fn prop_top_level_segments_disjoint(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            let mut top = top_level(&result.segment_decisions);
            top.sort_by_key(|s| s.start);
            for pair in top.windows(2) {
                prop_assert!(
                    pair[0].end <= pair[1].start,
                    "overlapping top-level segments: {:?} and {:?} for input {:?}",
                    pair[0], pair[1], input
                );
            }
        }

        /// The reason field is surfaced as a single value: a JSON string on
        /// the Claude Code hook surface (`permissionDecisionReason`) and a
        /// raw-printed line on the `may-i eval` TTY surface. A raw control
        /// character corrupts the latter (newline breaks the line, `\x1b`
        /// injects a terminal escape), so NO input-derived name may carry one
        /// unescaped. The spec requires "no raw newline or other control
        /// character"; assert exactly that, across every reason-producing path.
        #[test]
        fn prop_reason_is_single_line(input in arb_reason_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            if let Some(reason) = &result.reason {
                prop_assert!(
                    !reason.chars().any(|c| c.is_control()),
                    "reason carries a raw control character for {input:?}: {reason:?}"
                );
            }
        }

        /// `parse_error_reason` invariants — exercises the floor's
        /// reason helper directly so the property holds even on inputs
        /// where the floor wouldn't activate (decision already at Ask
        /// or above).
        #[test]
        fn prop_parse_error_reason_invariants(input in arb_input()) {
            let parse_result = may_i_shell_parser::parse(&input);
            let reason = parse_error_reason(&parse_result.diagnostics, &input);
            prop_assert!(!reason.contains('\n'), "reason: {reason:?}");
            prop_assert!(reason.starts_with("parse error: "), "reason: {reason:?}");
            if let Some(first_err) = parse_result
                .diagnostics
                .iter()
                .find(|d| d.severity == may_i_shell_parser::Severity::Error)
            {
                let expected = format!("parse error: {}", first_err.format_with_source(&input));
                prop_assert_eq!(&reason, &expected);
            }
        }

        #[test]
        fn prop_aggregate_matches_strictest_top_level(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            let top = top_level(&result.segment_decisions);
            if top.is_empty() {
                return Ok(());
            }
            let mut strictest = top[0].decision;
            // The aggregate is strictest over ALL units (top + nested), so
            // match the ALL-segments max here too. See engine semantics in
            // `evaluate_command_inner`.
            for s in &result.segment_decisions {
                if s.decision > strictest {
                    strictest = s.decision;
                }
            }
            prop_assert_eq!(strictest, result.decision);
        }

        /// For any shell input, `evaluate_authorised_string` produces the
        /// same decision as `evaluate_command` on the same input — modulo
        /// the `:via` push, which the rules in this fixture don't react
        /// to. The shared helper is the authorise-recursion path's
        /// re-entry into the top-level pipeline; the two must agree on
        /// the strictest-wins aggregation.
        #[test]
        fn prop_authorised_matches_top_level(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let top = evaluate_command(&input, &config, &empty_facts()).unwrap();
            let mut fold = PureFold;
            let auth = evaluate_authorised_string(
                &input,
                Some(&config),
                &empty_facts(),
                &mut fold,
                1,
                None,
                may_i_shell_parser::Dialect::Bash,
            )
            .unwrap();
            prop_assert_eq!(top.decision, auth.decision);
        }

        /// Equivalence guarantee: for any token list whose elements are
        /// all metacharacter-free, the new token-list helper SHALL
        /// agree with the old join-and-parse path on the decision.
        /// This is the regression-safety invariant — rules that
        /// authorised correctly under the old code path keep working.
        #[test]
        fn prop_tokens_match_string_when_metafree(
            tokens in proptest::collection::vec("[a-zA-Z0-9_./-]{1,8}", 1..6),
        ) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            for tok in &tokens {
                prop_assert!(!contains_shell_metacharacter(tok),
                    "strategy generated metacharacter-bearing token: {tok:?}");
            }
            let mut fold_s = PureFold;
            let mut fold_t = PureFold;
            let joined = tokens.join(" ");
            let from_string = evaluate_authorised_string(
                &joined,
                Some(&config),
                &empty_facts(),
                &mut fold_s,
                1,
                Some("wrapper"),
                may_i_shell_parser::Dialect::Bash,
            )
            .unwrap();
            let token_expansions = vec![None; tokens.len()];
            let from_tokens = evaluate_authorised_tokens(
                Argv::new(&tokens, &token_expansions),
                Some(&config),
                &empty_facts(),
                &mut fold_t,
                1,
                Some("wrapper"),
                may_i_shell_parser::Dialect::Bash,
            )
            .unwrap();
            prop_assert_eq!(from_string.decision, from_tokens.decision);
        }

        /// `parser-engine-invariants`: span-bounds property must hold even
        /// when the input contains POSIX `\<newline>` line continuations.
        /// Insertions are placed at fresh positions in the un-mutated base
        /// so each `\<NL>` lands in a clean (unquoted) context.
        #[test]
        fn prop_line_continuation_preserves_span_bounds(
            base in arb_input(),
            raw_positions in proptest::collection::vec(0usize..1000, 0..6),
        ) {
            let len = base.len();
            let mut positions: Vec<usize> = raw_positions
                .into_iter()
                .map(|p| if len == 0 { 0 } else { p % (len + 1) })
                .filter(|&p| base.is_char_boundary(p))
                .collect();
            positions.sort_unstable();

            let mut input = String::with_capacity(len + positions.len() * 2);
            let mut cursor = 0usize;
            for pos in positions {
                input.push_str(&base[cursor..pos]);
                input.push_str("\\\n");
                cursor = pos;
            }
            input.push_str(&base[cursor..]);

            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            for s in &result.segment_decisions {
                prop_assert!(
                    s.start <= s.end,
                    "segment {s:?} has start > end for input {input:?}"
                );
                prop_assert!(
                    s.end <= input.len(),
                    "segment {s:?} extends past input length {} for input {input:?}",
                    input.len()
                );
            }
        }
    }
}

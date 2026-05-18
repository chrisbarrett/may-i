use may_i_core::ast::Config;
use may_i_core::{ContextFacts, Decision, Keyword};
use may_i_shell_parser as parser;

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult, SegmentDecision};

use super::context::DEFAULT_RECURSION_LIMIT;
use super::decompose::{EvalUnit, decompose};
use super::entry::{evaluate_at_depth, evaluate_with_fold};

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

/// Evaluate a command string with a custom fold for tracing.
pub fn evaluate_command_with_fold<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    evaluate_command_inner(input, config, facts, fold, 0, DEFAULT_RECURSION_LIMIT, 0)
}

/// `outer_offset` is the byte offset of `input` within the outermost original
/// command being evaluated — added to every emitted `SegmentDecision` so
/// nested embedded recursions report ranges in outermost coordinates.
fn evaluate_command_inner<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    limit: usize,
    outer_offset: usize,
) -> Result<EvalResult, EvalError> {
    if depth >= limit {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!("recursion depth limit ({limit}) exceeded")),
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let parse_result = parser::parse(input);
    let diagnostics = parse_result.diagnostics.clone();
    let has_parse_errors = parse_result.has_errors();
    let units = decompose(&parse_result.command, input);

    if units.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason: Option<String> = None;
    let mut segment_decisions: Vec<SegmentDecision> = Vec::new();

    for unit in &units {
        let unit_span = unit.span();
        let result = match unit {
            EvalUnit::SimpleCommand { command, args, .. } => {
                evaluate_with_fold(command, args, config, facts, fold)?
            }
            EvalUnit::EmbeddedCommand { source, span } => {
                let embedded_result = evaluate_command_inner(
                    source,
                    config,
                    facts,
                    fold,
                    depth + 1,
                    limit,
                    outer_offset + span.0,
                )?;
                fold.embedded_command(source, embedded_result.decision);
                embedded_result
            }
            EvalUnit::DynamicCommand { reason, .. } => {
                let _out = fold.default_ask(reason);
                EvalResult::new(Decision::Ask, Some(reason.clone()))
            }
        };

        // SimpleCommand and DynamicCommand carry their own segment entries
        // (one per unit). EmbeddedCommand units are wrappers — they only
        // relay their child segments, otherwise the inner range would appear
        // twice (once as the embed unit, once as the child SimpleCommand).
        if !matches!(unit, EvalUnit::EmbeddedCommand { .. }) {
            segment_decisions.push(SegmentDecision {
                start: outer_offset + unit_span.0,
                end: outer_offset + unit_span.1,
                decision: result.decision,
            });
        }
        // Inner segments arrive in outermost coordinates already (offset
        // applied during recursion).
        segment_decisions.extend(result.segment_decisions);

        if result.decision >= aggregate_decision {
            aggregate_decision = result.decision;
            aggregate_reason = result.reason;
        }
    }

    // Error-severity parse diagnostics floor the decision at Ask. The same
    // floor applies per-segment so display can colour without re-running the
    // engine — a parse error means each segment's boundary is uncertain.
    if has_parse_errors {
        if aggregate_decision < Decision::Ask {
            aggregate_decision = Decision::Ask;
            aggregate_reason = Some(parse_error_reason(&diagnostics, input));
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
    Ok(eval_result)
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
) -> Result<EvalResult, EvalError> {
    if depth >= DEFAULT_RECURSION_LIMIT {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!(
                "recursion depth limit ({DEFAULT_RECURSION_LIMIT}) exceeded"
            )),
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some("empty command".to_string()),
        ));
    }

    let mut effective_facts = facts.clone();
    if let Some(name) = via_program
        && let Ok(key) = Keyword::new(":via")
    {
        effective_facts.insert_scalar(key, name);
    }

    let parse_result = parser::parse(input);
    let has_parse_errors = parse_result.has_errors();
    let units = decompose(&parse_result.command, input);

    if units.is_empty() {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some("empty command".to_string()),
        ));
    }

    let default_config = Config::default();
    let effective_config = config.unwrap_or(&default_config);

    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason: Option<String> = None;

    for unit in &units {
        let result = match unit {
            EvalUnit::SimpleCommand { command, args, .. } => evaluate_at_depth(
                command,
                args,
                effective_config,
                &effective_facts,
                fold,
                depth,
            )?,
            EvalUnit::EmbeddedCommand { source, .. } => {
                evaluate_authorised_string(source, config, &effective_facts, fold, depth + 1, None)?
            }
            EvalUnit::DynamicCommand { reason, .. } => {
                EvalResult::new(Decision::Ask, Some(reason.clone()))
            }
        };

        if result.decision >= aggregate_decision {
            aggregate_decision = result.decision;
            aggregate_reason = result.reason;
        }
    }

    if has_parse_errors && aggregate_decision < Decision::Ask {
        aggregate_decision = Decision::Ask;
        aggregate_reason = Some(parse_error_reason(&parse_result.diagnostics, input));
    }

    Ok(EvalResult::new(aggregate_decision, aggregate_reason))
}

/// Token-list sibling of [`evaluate_authorised_string`].
///
/// Used when the binding came in as `BindingValue::Tokens(_)` — e.g.
/// `(rest #cmd)`, `(positional #var *|+)`. Unlike the string helper,
/// this one does NOT re-parse argv. The outer shell already decomposed
/// the command line into tokens; joining them with single spaces and
/// re-parsing discards boundary information and exposes shell
/// metacharacters embedded in a single token (e.g. an outer-quoted
/// `-c` argument) as structure at the wrapper's frame. That's the
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
    tokens: &[String],
    config: Option<&Config>,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via_program: Option<&str>,
) -> Result<EvalResult, EvalError> {
    if depth >= DEFAULT_RECURSION_LIMIT {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!(
                "recursion depth limit ({DEFAULT_RECURSION_LIMIT}) exceeded"
            )),
        ));
    }

    if tokens.is_empty() {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some("empty command".to_string()),
        ));
    }

    if tokens.len() == 1 {
        // One token = one outer-shell boundary. No structural
        // information to preserve; re-parsing the lone element as a
        // command line is correct (it's how the user authored it).
        return evaluate_authorised_string(&tokens[0], config, facts, fold, depth, via_program);
    }

    let command = &tokens[0];
    if command.is_empty() || contains_shell_metacharacter(command) {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!(
                "dynamic or malformed inner command name: {command:?}"
            )),
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
        &tokens[1..],
        effective_config,
        &effective_facts,
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

    // -- Process substitution --

    #[test]
    fn process_substitution_both_allowed() {
        let config = config_with_rules(vec![allow_rule("diff"), allow_rule("ls")]);
        let result = evaluate_command("diff <(ls /a) <(ls /b)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Recursion depth limit --

    // -- Parse diagnostics --

    #[test]
    fn parse_error_reason_names_diagnostic_kind_and_location() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated single quote — Error severity. Reason should
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

        /// The reason field is consumed as a single JSON string value
        /// in the Claude Code hook surface (`permissionDecisionReason`).
        /// An embedded newline corrupts that surface; this invariant
        /// guards every reason-producing path at once.
        #[test]
        fn prop_reason_is_single_line(input in arb_input()) {
            let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
            let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
            if let Some(reason) = &result.reason {
                prop_assert!(
                    !reason.contains('\n'),
                    "multi-line reason for {input:?}: {reason:?}"
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
            )
            .unwrap();
            let from_tokens = evaluate_authorised_tokens(
                &tokens,
                Some(&config),
                &empty_facts(),
                &mut fold_t,
                1,
                Some("wrapper"),
            )
            .unwrap();
            prop_assert_eq!(from_string.decision, from_tokens.decision);
        }
    }
}

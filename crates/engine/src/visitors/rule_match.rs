// Visitor that matches resolved commands against config rules.
// Terminal visitor: always returns Terminal (never Continue).

use may_i_core::{Config, Decision, Effect, EvalResult, TraceEntry};
use may_i_shell_parser::SimpleCommand;
use crate::annotate::annotate_rule;
use crate::matcher::*;
use super::{CommandVisitor, VisitOutcome, VisitorContext};

/// Terminal visitor: matches the resolved command against config rules.
/// Always returns Terminal (never Continue).
pub(crate) struct RuleMatchVisitor;

impl CommandVisitor for RuleMatchVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let result = match_against_rules(resolved, ctx.config);
        VisitOutcome::Terminal {
            result,
            env: ctx.env.clone(),
        }
    }
}

/// Pure rule-matching logic: expand flags, iterate rules, return first match.
pub(crate) fn match_against_rules(
    resolved: &SimpleCommand,
    config: &Config,
) -> EvalResult {
    let cmd_name = match resolved.nonempty_command_name() {
        Some(name) => name,
        None => {
            return EvalResult::new(Decision::Ask, Some("Unknown command".into()));
        }
    };

    // Expand flags: -abc → -a -b -c (R8)
    let expanded_args = expand_flags(resolved.args());

    // Evaluate against rules: deny rules first, then first match
    let mut first_match: Option<EvalResult> = None;
    let mut trace = Vec::new();
    let mut had_command_match = false;

    for rule in &config.rules {
        if !command_matches(cmd_name, &rule.command) {
            continue;
        }

        had_command_match = true;
        let line_num = config.source_info.as_ref().map(|si| si.line_of(rule.source_span));
        let (doc, effect) = annotate_rule(rule, cmd_name, &expanded_args);
        trace.push(TraceEntry::Rule { doc, line: line_num });

        let effect = match effect {
            Some(eff) => eff,
            None => continue, // args didn't match
        };

        let Effect { decision, reason } = effect;
        let mut result = EvalResult::new(decision, reason);

        if decision == Decision::Deny {
            result.trace = trace;
            return result;
        }

        if first_match.is_none() {
            result.trace = trace.clone();
            first_match = Some(result);
        }
    }

    first_match.unwrap_or_else(|| {
        let reason = if had_command_match {
            format!("Rules for `{cmd_name}` exist but arguments did not match any patterns")
        } else {
            format!("No rule for command `{cmd_name}`")
        };
        trace.push(TraceEntry::DefaultAsk { reason: reason.clone() });
        let mut result = EvalResult::new(Decision::Ask, Some(reason));
        result.trace = trace;
        result
    })
}

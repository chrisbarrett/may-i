// Visitor that matches resolved commands against config rules.
// Terminal visitor: always returns Terminal (never Continue).

use may_i_core::{Config, Decision, Effect, EvalResult, RuleBody, TraceStep};
use may_i_shell_parser::SimpleCommand;
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
        trace.push(TraceStep::Rule {
            label: rule.command.to_string(),
            line: line_num,
        });

        let effect = match &rule.body {
            RuleBody::Effect { matcher: None, effect } => {
                effect.clone()
            }
            RuleBody::Effect { matcher: Some(m), effect } => {
                let mut collector = TraceCollector::new();
                let outcome = match_args(m, &expanded_args, &mut |ev| collector.on_event(ev));
                trace.extend(collector.into_steps());
                if matches!(outcome, MatchOutcome::NoMatch) {
                    trace.push(TraceStep::ArgsNotMatched);
                    continue;
                }
                trace.push(TraceStep::ArgsMatched);
                // Prefer the embedded effect if the matcher produced one,
                // otherwise fall back to the rule-level effect.
                if let MatchOutcome::Matched(eff) = outcome {
                    eff
                } else {
                    effect.clone()
                }
            }
            RuleBody::Branching(m) => {
                let mut collector = TraceCollector::new();
                let outcome = match_args(m, &expanded_args, &mut |ev| collector.on_event(ev));
                trace.extend(collector.into_steps());
                match outcome {
                    MatchOutcome::Matched(eff) => {
                        trace.push(TraceStep::ArgsMatched);
                        eff
                    }
                    _ => {
                        trace.push(TraceStep::ArgsNotMatched);
                        continue;
                    }
                }
            }
        };

        trace.push(TraceStep::Effect {
            decision: effect.decision,
            reason: effect.reason.clone(),
        });

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
        trace.push(TraceStep::DefaultAsk);
        let mut result = EvalResult::new(Decision::Ask, Some(reason));
        result.trace = trace;
        result
    })
}

// ── Trace collector ────────────────────────────────────────────────

/// Collects MatchEvents into structured TraceStep values.
struct TraceCollector {
    steps: Vec<TraceStep>,
}

impl TraceCollector {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    fn on_event(&mut self, ev: MatchEvent<'_>) {
        match ev {
            MatchEvent::ExprVsArg { expr, arg, matched } => {
                self.steps.push(TraceStep::ExprVsArg {
                    expr: expr.to_string(),
                    arg: resolved_arg_to_string(arg),
                    matched,
                });
            }
            MatchEvent::Quantifier { pexpr, count, matched } => {
                self.steps.push(TraceStep::Quantifier {
                    label: pexpr.to_string(),
                    count,
                    matched,
                });
            }
            MatchEvent::Missing { pexpr } => {
                self.steps.push(TraceStep::Missing {
                    label: pexpr.to_string(),
                });
            }
            MatchEvent::ExprCondBranch { test, matched, effect } => {
                if matched {
                    self.steps.push(TraceStep::ExprCondBranch {
                        label: test.to_string(),
                        decision: effect.decision,
                    });
                }
            }
            MatchEvent::MatcherCondBranch { matched, effect } => {
                if matched {
                    self.steps.push(TraceStep::MatcherCondBranch {
                        decision: effect.decision,
                    });
                }
            }
            MatchEvent::MatcherCondElse { effect } => {
                self.steps.push(TraceStep::MatcherCondElse {
                    decision: effect.decision,
                });
            }
            MatchEvent::Anywhere { expr, args, matched } => {
                self.steps.push(TraceStep::Anywhere {
                    label: format!("(anywhere {})", expr),
                    args: args.iter().map(resolved_arg_to_string).collect(),
                    matched,
                });
            }
            MatchEvent::ExactRemainder { count } => {
                self.steps.push(TraceStep::ExactRemainder { count });
            }
        }
    }

    fn into_steps(self) -> Vec<TraceStep> {
        self.steps
    }
}

fn resolved_arg_to_string(a: &ResolvedArg) -> String {
    match a {
        ResolvedArg::Literal(s) => format!("\"{s}\""),
        ResolvedArg::Opaque => "<opaque>".into(),
    }
}

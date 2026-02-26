// Visitor that matches resolved commands against config rules.
// Terminal visitor: always returns Terminal (never Continue).

use may_i_core::{Config, Decision, Effect, EvalResult};
use may_i_shell_parser::SimpleCommand;
use super::matcher::*;
use super::visitor::{CommandVisitor, VisitOutcome, VisitorContext};

/// Terminal visitor: matches the resolved command against config rules.
/// Always returns Terminal (never Continue).
pub(in crate::engine) struct RuleMatchVisitor;

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
pub(in crate::engine) fn match_against_rules(
    resolved: &SimpleCommand,
    config: &Config,
) -> EvalResult {
    let cmd_name = match resolved.command_name() {
        Some(name) if !name.is_empty() => name,
        _ => {
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
        let line_num = config.source_info.as_ref().map(|si| {
            may_i_sexpr::offset_to_line_col(&si.content, rule.source_span.start).0
        });
        let line_prefix = line_num.map(|n| format!("{n}: ")).unwrap_or_default();
        let rule_label = format_command_matcher(
            &rule.command,
            line_prefix.len() + "rule ".len(),
        );
        for (i, line) in rule_label.lines().enumerate() {
            if i == 0 {
                trace.push(format!("{line_prefix}rule {line}"));
            } else {
                trace.push(line.to_string());
            }
        }

        let outcome = match &rule.matcher {
            None => MatchOutcome::MatchedNoEffect,
            Some(m) => {
                let mut collector = TraceCollector::new(2);
                let outcome = match_args(m, &expanded_args, &mut |ev| collector.on_event(ev));
                for step in collector.into_steps() {
                    for line in step.lines() {
                        trace.push(format!("  {line}"));
                    }
                }
                outcome
            }
        };

        let effect = match outcome {
            MatchOutcome::NoMatch => {
                if rule.matcher.is_some() {
                    trace.push("  args did not match".into());
                }
                continue;
            }
            MatchOutcome::Matched(eff) => {
                if rule.matcher.is_some() {
                    trace.push("  args matched".into());
                }
                trace.push(format!(
                    "  effect: {} — {}",
                    eff.decision,
                    eff.reason.as_deref().unwrap_or("(no reason)")
                ));
                eff
            }
            MatchOutcome::MatchedNoEffect => {
                if rule.matcher.is_some() {
                    trace.push("  args matched".into());
                }
                match &rule.effect {
                    Some(eff) => {
                        trace.push(format!(
                            "  effect: {} — {}",
                            eff.decision,
                            eff.reason.as_deref().unwrap_or("(no reason)")
                        ));
                        eff.clone()
                    }
                    None => continue,
                }
            }
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
        trace.push("  => ask (default)".into());
        let mut result = EvalResult::new(Decision::Ask, Some(reason));
        result.trace = trace;
        result
    })
}

// ── Trace collector ────────────────────────────────────────────────

/// Collects MatchEvents into human-readable trace strings.
struct TraceCollector {
    steps: Vec<String>,
    /// Column at which trace expressions start (for pp wrapping).
    indent: usize,
}

impl TraceCollector {
    fn new(indent: usize) -> Self {
        Self { steps: Vec::new(), indent }
    }

    /// Pretty-print a Doc at the current indent.
    fn pp(&self, doc: &may_i_pp::Doc) -> String {
        may_i_pp::pretty(doc, self.indent, &may_i_pp::Format { width: PP_WIDTH, ..Default::default() })
    }

    fn on_event(&mut self, ev: MatchEvent<'_>) {
        match ev {
            MatchEvent::ExprVsArg { expr, arg, matched } => {
                let result = if matched { "yes" } else { "no" };
                let lhs = self.pp(&expr_to_doc(expr));
                let rhs = self.pp(&resolved_arg_to_doc(arg));
                self.steps.push(format!("{lhs} vs {rhs} => {result}"));
            }
            MatchEvent::EnterOptional => {}
            MatchEvent::LeaveOptional => {}
            MatchEvent::Quantifier { pexpr, count, matched } => {
                let result = if matched {
                    format!("yes (matched {count})")
                } else {
                    "no".into()
                };
                let label = self.pp(&pos_expr_to_doc(pexpr));
                self.steps.push(format!("{label} => {result}"));
            }
            MatchEvent::Missing { pexpr } => {
                let label = self.pp(&pos_expr_to_doc(pexpr));
                self.steps.push(format!("{label} vs <missing> => no"));
            }
            MatchEvent::EnterCond => {}
            MatchEvent::ExprCondBranch { test, matched, effect } => {
                if matched {
                    let label = self.pp(&expr_to_doc(test));
                    self.steps.push(format!("{label} => yes [{}]", effect.decision));
                }
            }
            MatchEvent::MatcherCondBranch { matched, effect } => {
                if matched {
                    self.steps.push(format!("=> yes [{}]", effect.decision));
                }
            }
            MatchEvent::MatcherCondElse { effect } => {
                self.steps.push(format!("else => [{}]", effect.decision));
            }
            MatchEvent::LeaveCond => {}
            MatchEvent::Anywhere { expr, matched } => {
                let result = if matched { "yes" } else { "no" };
                let doc = may_i_pp::Doc::list(vec![
                    may_i_pp::Doc::atom("anywhere"),
                    expr_to_doc(expr),
                ]);
                let label = self.pp(&doc);
                self.steps.push(format!("{label} => {result}"));
            }
            MatchEvent::ExactRemainder { count } => {
                self.steps.push(format!("exact: {count} positional args remaining"));
            }
        }
    }

    fn into_steps(self) -> Vec<String> {
        self.steps
    }
}

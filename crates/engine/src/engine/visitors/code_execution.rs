// Visitor that detects code-execution constructs (source, eval, bash -c)
// and either returns Ask or requests recursion into the inner command.

use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, SimpleCommand};
use super::{CommandVisitor, VisitOutcome, VisitorContext, MAX_EVAL_DEPTH};

/// Detects `source`/`.`, opaque command names, `eval`, and `bash/sh/zsh -c`.
///
/// - `source`/`.`: always Ask (file contents unknown).
/// - Opaque command name: Ask (can't determine what runs).
/// - `eval`: concatenate literal args and Recurse, or Ask if opaque.
/// - `bash -c` / `sh -c` / `zsh -c`: Recurse into the `-c` argument.
pub(in crate::engine) struct CodeExecutionVisitor;

impl CommandVisitor for CodeExecutionVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let cmd_name = match resolved.command_name() {
            Some(name) => name,
            None => return VisitOutcome::Continue,
        };

        // source / . — always Ask
        if cmd_name == "source" || cmd_name == "." {
            return VisitOutcome::Terminal {
                result: EvalResult::new(
                    Decision::Ask,
                    Some(format!(
                        "Cannot statically analyse `{cmd_name}`: sourced file contents are unknown"
                    )),
                ),
                env: ctx.env.clone(),
            };
        }

        // Opaque variable as command name
        if resolved.words.first().is_some_and(|w| w.has_opaque_parts()) {
            return VisitOutcome::Terminal {
                result: EvalResult::new(
                    Decision::Ask,
                    Some("Variable used as command name: cannot determine what runs".into()),
                ),
                env: ctx.env.clone(),
            };
        }

        // eval
        if cmd_name == "eval" && ctx.depth < MAX_EVAL_DEPTH {
            return self.visit_eval(ctx, resolved);
        }

        // bash -c / sh -c / zsh -c
        if matches!(cmd_name, "bash" | "sh" | "zsh")
            && ctx.depth < MAX_EVAL_DEPTH
            && let Some(outcome) = self.visit_shell_dash_c(ctx, resolved)
        {
            return outcome;
        }

        VisitOutcome::Continue
    }
}

impl CodeExecutionVisitor {
    fn visit_eval(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
        let args = resolved.args();

        if args.is_empty() {
            return VisitOutcome::Terminal {
                result: EvalResult::new(Decision::Allow, None),
                env: ctx.env.clone(),
            };
        }

        // Opaque args: safe but unknown value
        if args.iter().any(|a| a.has_opaque_parts()) {
            return VisitOutcome::Terminal {
                result: EvalResult::new(
                    Decision::Ask,
                    Some("Cannot determine eval'd command: argument value is unknown".into()),
                ),
                env: ctx.env.clone(),
            };
        }

        // All args are literal — concatenate and recurse
        let eval_str: String = args.iter().map(|a| a.to_str()).collect::<Vec<_>>().join(" ");
        let inner_ast = parser::parse(&eval_str);
        VisitOutcome::Recurse {
            command: inner_ast,
            env: ctx.env.clone(),
        }
    }

    fn visit_shell_dash_c(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> Option<VisitOutcome> {
        let args = resolved.args();

        let mut found_c = false;
        let mut cmd_arg = None;
        for arg in args {
            let s = arg.to_str();
            if found_c {
                cmd_arg = Some(arg);
                break;
            }
            if s == "-c" {
                found_c = true;
            }
        }

        if !found_c {
            return None;
        }

        let cmd_arg = cmd_arg?;

        if cmd_arg.has_dynamic_parts() {
            return None; // fall through to rule matching
        }

        if cmd_arg.has_opaque_parts() {
            return Some(VisitOutcome::Terminal {
                result: EvalResult::new(
                    Decision::Ask,
                    Some(format!(
                        "Cannot determine `{} -c` command: argument value is unknown",
                        resolved.command_name().unwrap_or("sh"),
                    )),
                ),
                env: ctx.env.clone(),
            });
        }

        let cmd_str = cmd_arg.to_str();
        let inner_ast = parser::parse(&cmd_str);
        Some(VisitOutcome::Recurse {
            command: inner_ast,
            env: ctx.env.clone(),
        })
    }
}

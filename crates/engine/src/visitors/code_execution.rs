// Visitor that detects code-execution constructs (source, eval, bash -c)
// and either returns Ask or requests recursion into the inner command.

use super::{CommandVisitor, MAX_EVAL_DEPTH, VisitOutcome, VisitorContext};
use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, SimpleCommand};

/// Detects `source`/`.`, opaque command names, `eval`, and `bash/sh/zsh -c`.
///
/// - `source`/`.`: always Ask (file contents unknown).
/// - Opaque command name: Ask (can't determine what runs).
/// - `eval`: concatenate literal args and Recurse, or Ask if opaque.
/// - `bash -c` / `sh -c` / `zsh -c`: Recurse into the `-c` argument.
pub(crate) struct CodeExecutionVisitor;

impl CommandVisitor for CodeExecutionVisitor {
    fn visit_simple_command(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
        // Opaque variable as command name (must check before nonempty_command_name
        // since opaque commands resolve to an empty name)
        if resolved.words.first().is_some_and(|w| w.has_opaque_parts()) {
            return VisitOutcome::Terminal {
                result: EvalResult::new(
                    Decision::Ask,
                    Some("Variable used as command name: cannot determine what runs".into()),
                ),
                env: ctx.env.clone(),
            };
        }

        let cmd_name = match resolved.nonempty_command_name() {
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
        let eval_str: String = args
            .iter()
            .map(|a| a.to_str())
            .collect::<Vec<_>>()
            .join(" ");
        let inner_ast = parser::parse(&eval_str);
        VisitOutcome::Recurse {
            command: inner_ast,
            env: ctx.env.clone(),
            context: ctx.context.clone(),
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
            context: ctx.context.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::var_env::VarEnv;
    use may_i_core::Config;
    use may_i_shell_parser::{self as parser, Command};

    fn test_context() -> VisitorContext<'static> {
        let config = Box::leak(Box::new(Config::default()));
        let context = Box::leak(Box::new(may_i_core::ContextFacts::default()));
        let env = Box::leak(Box::new(VarEnv::from_process_env()));
        VisitorContext {
            config,
            context,
            env,
            depth: 0,
        }
    }

    fn simple_cmd(cmd: &str) -> SimpleCommand {
        match parser::parse(cmd) {
            Command::Simple(sc) => sc,
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn source_command_returns_ask() {
        let ctx = test_context();
        let cmd = simple_cmd("source file.sh");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { result, .. } => {
                assert_eq!(result.decision, Decision::Ask);
                assert!(result.reason.unwrap().contains("source"));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn dot_command_returns_ask() {
        let ctx = test_context();
        let cmd = simple_cmd(". file.sh");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { result, .. } => {
                assert_eq!(result.decision, Decision::Ask);
                assert!(result.reason.unwrap().contains("."));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn bash_without_c_flag_continues() {
        let ctx = test_context();
        let cmd = simple_cmd("bash script.sh");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {
                // Correctly continues to next visitor
            }
            _ => panic!("Expected continue outcome"),
        }
    }

    #[test]
    fn regular_command_continues() {
        let ctx = test_context();
        let cmd = simple_cmd("ls -la");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {
                // Correctly continues
            }
            _ => panic!("Expected continue outcome"),
        }
    }

    #[test]
    fn eval_at_max_depth_continues() {
        let ctx = VisitorContext {
            config: test_context().config,
            context: test_context().context,
            env: &VarEnv::from_process_env(),
            depth: MAX_EVAL_DEPTH,
        };
        let cmd = simple_cmd("eval echo hello");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {
                // Correctly continues at max depth
            }
            _ => panic!("Expected continue outcome at max depth"),
        }
    }

    #[test]
    fn bash_c_at_max_depth_continues() {
        let ctx = VisitorContext {
            config: test_context().config,
            context: test_context().context,
            env: &VarEnv::from_process_env(),
            depth: MAX_EVAL_DEPTH,
        };
        let cmd = simple_cmd("bash -c 'echo hello'");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {
                // Correctly continues at max depth
            }
            _ => panic!("Expected continue outcome at max depth"),
        }
    }

    #[test]
    fn eval_concatenates_multiple_args() {
        let ctx = test_context();
        let cmd = simple_cmd("eval echo hello world");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse { command, .. } => {
                // The inner command should have multiple words
                if let Command::Simple(sc) = command {
                    assert_eq!(sc.words.len(), 3); // echo, hello, world
                } else {
                    panic!("Expected simple command");
                }
            }
            _ => panic!("Expected recurse outcome"),
        }
    }

    #[test]
    fn eval_with_no_args_returns_allow() {
        let ctx = test_context();
        let cmd = simple_cmd("eval");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { result, .. } => {
                assert_eq!(result.decision, Decision::Allow);
                assert!(result.reason.is_none());
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn sh_c_command_recurses() {
        let ctx = test_context();
        let cmd = simple_cmd("sh -c 'echo hello'");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse { command, .. } => {
                if let Command::Simple(sc) = command {
                    assert_eq!(sc.nonempty_command_name().unwrap(), "echo");
                } else {
                    panic!("Expected simple command");
                }
            }
            _ => panic!("Expected recurse outcome"),
        }
    }

    #[test]
    fn zsh_c_command_recurses() {
        let ctx = test_context();
        let cmd = simple_cmd("zsh -c 'ls -la'");
        let visitor = CodeExecutionVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse { command, .. } => {
                if let Command::Simple(sc) = command {
                    assert_eq!(sc.nonempty_command_name().unwrap(), "ls");
                } else {
                    panic!("Expected simple command");
                }
            }
            _ => panic!("Expected recurse outcome"),
        }
    }
}

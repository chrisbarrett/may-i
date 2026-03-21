// Visitor that peels known wrapper commands (e.g. sudo, env) and
// recurses into the inner command.

use super::{CommandVisitor, VisitOutcome, VisitorContext};
use crate::matcher::unwrap_wrapper;
use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, Command, SimpleCommand};

/// Peels known wrapper commands and recurses into the inner command.
/// If the inner command is a single word containing spaces, it is
/// parsed as a full AST.
pub(crate) struct WrapperUnwrapVisitor;

impl CommandVisitor for WrapperUnwrapVisitor {
    fn visit_simple_command(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
        let cmd_name = match resolved.nonempty_command_name() {
            Some(name) => name,
            None => return VisitOutcome::Continue,
        };

        let inner = match unwrap_wrapper(resolved, ctx.config) {
            Some(inner) => inner,
            None => return VisitOutcome::Continue,
        };
        let next_context = ctx.context.merge(&inner.facts);

        // Single-word inner command may contain spaces (e.g. from variable expansion)
        if inner.command.words.len() == 1 {
            let word = &inner.command.words[0];
            if word.has_opaque_parts() {
                return VisitOutcome::Terminal {
                    result: EvalResult::new(
                        Decision::Ask,
                        Some(format!(
                            "Cannot determine inner command for `{cmd_name}`: \
                             argument value is unknown"
                        )),
                    ),
                    env: ctx.env.clone(),
                };
            }
            let s = word.to_str();
            if s.contains(' ') {
                let inner_ast = parser::parse(&s);
                return VisitOutcome::Recurse {
                    command: inner_ast,
                    env: ctx.env.clone(),
                    context: next_context,
                };
            }
        }

        VisitOutcome::Recurse {
            command: Command::Simple(inner.command),
            env: ctx.env.clone(),
            context: next_context,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::var_env::VarEnv;
    use may_i_core::{Config, ContextFacts, Expr, Wrapper, WrapperPattern, WrapperStep};
    use may_i_shell_parser::{self as parser, Command};

    fn simple_cmd(cmd: &str) -> SimpleCommand {
        match parser::parse(cmd) {
            Command::Simple(sc) => sc,
            _ => panic!("Expected simple command"),
        }
    }

    fn wrapper_pattern_exact(text: &str) -> WrapperPattern {
        WrapperPattern {
            expr: Expr::Literal(text.to_string()),
            bind_fact: None,
        }
    }

    fn wrapper_pattern_capture(fact: &str) -> WrapperPattern {
        WrapperPattern {
            expr: Expr::Wildcard,
            bind_fact: Some(fact.to_string()),
        }
    }

    fn context_with_wrappers(wrappers: Vec<Wrapper>) -> VisitorContext<'static> {
        let mut config = Config::default();
        config.wrappers = wrappers;
        let config = Box::leak(Box::new(config));
        let context = Box::leak(Box::new(ContextFacts::default()));
        let env = Box::leak(Box::new(VarEnv::from_process_env()));
        VisitorContext {
            config,
            context,
            env,
            depth: 0,
        }
    }

    #[test]
    fn non_wrapper_command_continues() {
        let ctx = context_with_wrappers(vec![]);
        let cmd = simple_cmd("ls -la");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn sudo_wrapper_unwraps_command() {
        let wrapper = Wrapper {
            command: "sudo".to_string(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![],
                capture: true,
            }],
        };
        let ctx = context_with_wrappers(vec![wrapper]);
        let cmd = simple_cmd("sudo ls -la");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse {
                command,
                context: ctx_facts,
                ..
            } => {
                if let Command::Simple(sc) = command {
                    assert_eq!(sc.words.len(), 2);
                    assert!(sc.nonempty_command_name().unwrap().contains("ls"));
                } else {
                    panic!("Expected Simple command");
                }
                assert!(ctx_facts.has(":via/sudo"));
            }
            _ => panic!("Expected Recurse"),
        }
    }

    #[test]
    fn wrapper_with_literal_inner_command_recurses() {
        let wrapper = Wrapper {
            command: "sudo".to_string(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![],
                capture: true,
            }],
        };
        let ctx = context_with_wrappers(vec![wrapper]);
        let cmd = simple_cmd("sudo ls -la");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse { command, .. } => {
                if let Command::Simple(sc) = command {
                    assert!(sc.nonempty_command_name().unwrap().contains("ls"));
                } else {
                    panic!("Expected Simple command");
                }
            }
            _ => panic!("Expected Recurse"),
        }
    }

    #[test]
    fn empty_wrapper_steps_does_not_unwrap() {
        let wrapper = Wrapper {
            command: "wrapper".to_string(),
            steps: vec![],
        };
        let ctx = context_with_wrappers(vec![wrapper]);
        let cmd = simple_cmd("wrapper cmd");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue for wrapper with empty steps"),
        }
    }

    #[test]
    fn wrapper_mismatch_continues() {
        let wrapper = Wrapper {
            command: "sudo".to_string(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![wrapper_pattern_exact("-u")],
                capture: false,
            }],
        };
        let ctx = context_with_wrappers(vec![wrapper]);
        let cmd = simple_cmd("sudo ls");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue when wrapper pattern doesn't match"),
        }
    }

    #[test]
    fn wrapper_captures_fact_bindings() {
        let wrapper = Wrapper {
            command: "ssh".to_string(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![wrapper_pattern_capture(":ssh/host")],
                capture: true,
            }],
        };
        let ctx = context_with_wrappers(vec![wrapper]);
        let cmd = simple_cmd("ssh myserver ls");
        let visitor = WrapperUnwrapVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse {
                context: ctx_facts, ..
            } => {
                assert!(ctx_facts.has(":via/ssh"));
                assert_eq!(ctx_facts.get_scalar(":ssh/host"), Some("myserver"));
            }
            _ => panic!("Expected Recurse with facts"),
        }
    }
}

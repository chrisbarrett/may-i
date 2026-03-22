// Visitor that handles shell function calls by inlining the function body.

use super::{CommandVisitor, MAX_EVAL_DEPTH, VisitOutcome, VisitorContext};
use crate::var_env::VarState;
use may_i_shell_parser::SimpleCommand;

/// When the command name matches a previously defined function, set up
/// positional parameters and recurse into the function body.
pub(crate) struct FunctionCallVisitor;

impl CommandVisitor for FunctionCallVisitor {
    fn visit_simple_command(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
        let cmd_name = match resolved.nonempty_command_name() {
            Some(name) => name,
            None => return VisitOutcome::Continue,
        };

        if ctx.depth >= MAX_EVAL_DEPTH {
            return VisitOutcome::Continue;
        }

        let body = match ctx.env.get_fn(cmd_name) {
            Some(body) => body.clone(),
            None => return VisitOutcome::Continue,
        };

        // Set up positional parameters ($1, $2, ...) from the call arguments
        let mut fn_env = ctx.env.clone();
        for (i, arg) in resolved.args().iter().enumerate() {
            let state = if arg.is_literal() {
                VarState::Known(arg.to_str())
            } else if arg.has_opaque_parts() {
                VarState::Opaque
            } else {
                VarState::Unsafe
            };
            fn_env.set(format!("{}", i + 1), state);
        }

        VisitOutcome::Recurse {
            command: body,
            env: fn_env,
            context: ctx.context.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::var_env::VarEnv;
    use may_i_core::{Config, ContextFacts};
    use may_i_shell_parser::{self as parser, Command, SimpleCommand};

    fn simple_cmd(cmd: &str) -> SimpleCommand {
        match parser::parse(cmd) {
            Command::Simple(sc) => sc,
            _ => panic!("Expected simple command"),
        }
    }

    fn test_context() -> VisitorContext<'static> {
        let config = Box::leak(Box::new(Config::default()));
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
    fn non_function_command_continues() {
        let ctx = test_context();
        let cmd = simple_cmd("ls -la");
        let visitor = FunctionCallVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue for non-function"),
        }
    }

    #[test]
    fn at_max_depth_continues() {
        let base_ctx = test_context();
        let ctx = VisitorContext {
            config: base_ctx.config,
            context: base_ctx.context,
            env: base_ctx.env,
            depth: MAX_EVAL_DEPTH,
        };
        let cmd = simple_cmd("myfunc arg1");
        let visitor = FunctionCallVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue at max depth"),
        }
    }

    #[test]
    fn function_call_with_literal_args() {
        let ctx = test_context();
        let mut env = VarEnv::from_process_env();
        let body = parser::parse("echo hello");
        env.set_fn("myfunc".to_string(), body);
        let env_leak = Box::leak(Box::new(env));

        let ctx = VisitorContext {
            config: ctx.config,
            context: ctx.context,
            env: env_leak,
            depth: 0,
        };

        let cmd = simple_cmd("myfunc arg1 arg2");
        let visitor = FunctionCallVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Recurse {
                command: _,
                env,
                context: _,
            } => {
                // Verify positional parameters were set
                match env.get("1") {
                    Some(VarState::Known(val)) => assert_eq!(val, "arg1"),
                    other => panic!("Expected $1 to be Known('arg1'), got {:?}", other),
                }
                match env.get("2") {
                    Some(VarState::Known(val)) => assert_eq!(val, "arg2"),
                    other => panic!("Expected $2 to be Known('arg2'), got {:?}", other),
                }
            }
            _ => panic!("Expected Recurse outcome"),
        }
    }
}

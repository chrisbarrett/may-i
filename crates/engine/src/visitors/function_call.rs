// Visitor that handles shell function calls by inlining the function body.

use may_i_shell_parser::SimpleCommand;
use crate::var_env::VarState;
use super::{CommandVisitor, VisitOutcome, VisitorContext, MAX_EVAL_DEPTH};

/// When the command name matches a previously defined function, set up
/// positional parameters and recurse into the function body.
pub(crate) struct FunctionCallVisitor;

impl CommandVisitor for FunctionCallVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
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
        }
    }
}

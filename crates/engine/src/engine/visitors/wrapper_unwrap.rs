// Visitor that peels known wrapper commands (e.g. sudo, env) and
// recurses into the inner command.

use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, Command, SimpleCommand};
use super::super::matcher::unwrap_wrapper;
use super::traits::{CommandVisitor, VisitOutcome, VisitorContext};

/// Peels known wrapper commands and recurses into the inner command.
/// If the inner command is a single word containing spaces, it is
/// parsed as a full AST.
pub(in crate::engine) struct WrapperUnwrapVisitor;

impl CommandVisitor for WrapperUnwrapVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let cmd_name = match resolved.command_name() {
            Some(name) if !name.is_empty() => name,
            _ => return VisitOutcome::Continue,
        };

        let inner = match unwrap_wrapper(resolved, ctx.config) {
            Some(inner) => inner,
            None => return VisitOutcome::Continue,
        };

        // Single-word inner command may contain spaces (e.g. from variable expansion)
        if inner.words.len() == 1 {
            let word = &inner.words[0];
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
                };
            }
        }

        VisitOutcome::Recurse {
            command: Command::Simple(inner),
            env: ctx.env.clone(),
        }
    }
}

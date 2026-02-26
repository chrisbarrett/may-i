// Visitor that detects unresolvable dynamic parts in a resolved command.

use may_i_shell_parser::SimpleCommand;
use super::{CommandVisitor, VisitOutcome, VisitorContext, dynamic_ask};

/// Returns `Ask` when a resolved command still contains dynamic parts
/// (unsafe variables, command substitutions, etc.) that prevent static analysis.
pub(in crate::engine) struct DynamicPartsVisitor;

impl CommandVisitor for DynamicPartsVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let mut dynamic = Vec::new();
        for word in &resolved.words {
            dynamic.extend(word.dynamic_parts());
        }
        for assignment in &resolved.assignments {
            dynamic.extend(assignment.value.dynamic_parts());
        }
        for redir in &resolved.redirections {
            if let may_i_shell_parser::RedirectionTarget::File(w) = &redir.target {
                dynamic.extend(w.dynamic_parts());
            }
        }

        if dynamic.is_empty() {
            return VisitOutcome::Continue;
        }

        let cmd_label = resolved.command_name().unwrap_or("<unknown>");
        VisitOutcome::Terminal {
            result: dynamic_ask(&dynamic, &format!("Command `{cmd_label}` contains")),
            env: ctx.env.clone(),
        }
    }
}

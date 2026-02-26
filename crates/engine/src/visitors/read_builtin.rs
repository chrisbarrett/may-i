// Visitor that handles `read`, `readarray`, and `mapfile` builtins
// by marking the target variables as safe in the environment.

use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, SimpleCommand};
use crate::var_env::VarState;
use super::{CommandVisitor, VisitOutcome, VisitorContext};

/// Detects `read`/`readarray`/`mapfile` and updates the variable
/// environment to mark target variables as safe (value unknown at
/// analysis time, but user-controlled input is considered safe).
pub(crate) struct ReadBuiltinVisitor;

impl CommandVisitor for ReadBuiltinVisitor {
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let cmd_name = match resolved.command_name() {
            Some(name) if matches!(name, "read" | "readarray" | "mapfile") => name,
            _ => return VisitOutcome::Continue,
        };

        // Flags that take an argument (the next token is consumed)
        let flags_with_arg: &[&str] = match cmd_name {
            "read" => &["-d", "-n", "-N", "-p", "-t", "-u"],
            "readarray" | "mapfile" => &["-d", "-n", "-O", "-t", "-u", "-C", "-c"],
            _ => &[],
        };

        // Extract variable names from args (skip flags and their values)
        let args = resolved.args();
        let mut var_names = Vec::new();
        let mut skip_value = false;
        for arg in args {
            let s = arg.to_str();
            if skip_value {
                skip_value = false;
                continue;
            }
            if s.starts_with('-') && s.len() > 1 {
                skip_value = flags_with_arg.iter().any(|f| *f == s);
                continue;
            }
            var_names.push(s);
        }

        // Check for herestring with literal value
        let herestring_val = resolved.redirections.iter().find_map(|r| {
            if matches!(r.kind, parser::RedirectionKind::Herestring)
                && let parser::RedirectionTarget::File(w) = &r.target
                && w.is_literal()
            {
                return Some(w.to_str());
            }
            None
        });

        // Default variable name for `read` is REPLY
        if var_names.is_empty() && cmd_name == "read" {
            var_names.push("REPLY".to_string());
        }

        // Set variables: if herestring with known value and single var, use it;
        // otherwise Safe(None) (user-controlled input is safe but unknown)
        let mut new_env = ctx.env.clone();
        for (i, name) in var_names.iter().enumerate() {
            let state = if var_names.len() == 1 && i == 0 {
                match &herestring_val {
                    Some(val) => VarState::Known(val.clone()),
                    None => VarState::Opaque,
                }
            } else {
                VarState::Opaque
            };
            new_env.set(name.clone(), state);
        }

        VisitOutcome::Terminal {
            result: EvalResult::new(Decision::Allow, None),
            env: new_env,
        }
    }
}

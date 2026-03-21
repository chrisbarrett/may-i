// Visitor that handles `read`, `readarray`, and `mapfile` builtins
// by marking the target variables as safe in the environment.

use super::{CommandVisitor, VisitOutcome, VisitorContext};
use crate::var_env::VarState;
use may_i_core::{Decision, EvalResult};
use may_i_shell_parser::{self as parser, SimpleCommand};

/// Detects `read`/`readarray`/`mapfile` and updates the variable
/// environment to mark target variables as safe (value unknown at
/// analysis time, but user-controlled input is considered safe).
pub(crate) struct ReadBuiltinVisitor;

impl CommandVisitor for ReadBuiltinVisitor {
    fn visit_simple_command(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::var_env::{VarEnv, VarState};
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
    fn read_with_varname_sets_opaque() {
        let ctx = test_context();
        let cmd = simple_cmd("read varname");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, result } => {
                assert_eq!(result.decision, Decision::Allow);
                let state = env.get("varname");
                assert!(matches!(state, Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn read_without_args_sets_reply() {
        let ctx = test_context();
        let cmd = simple_cmd("read");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                let state = env.get("REPLY");
                assert!(matches!(state, Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn read_with_herestring_sets_known_value() {
        let ctx = test_context();
        let cmd = simple_cmd("read varname <<< 'hello world'");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                let state = env.get("varname");
                assert!(matches!(state, Some(VarState::Known(v)) if v == "hello world"));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn readarray_sets_opaque() {
        let ctx = test_context();
        let cmd = simple_cmd("readarray arr");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                let state = env.get("arr");
                assert!(matches!(state, Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn mapfile_sets_opaque() {
        let ctx = test_context();
        let cmd = simple_cmd("mapfile arr");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                let state = env.get("arr");
                assert!(matches!(state, Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn read_with_flags_skips_flag_values() {
        let ctx = test_context();
        let cmd = simple_cmd("read -p 'prompt: ' -t 5 varname");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                // Should only set varname, not -p or -t values
                let state = env.get("varname");
                assert!(matches!(state, Some(VarState::Opaque)));
                assert!(env.get("prompt:").is_none());
                assert!(env.get("5").is_none());
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn readarray_with_flags_skips_flag_values() {
        let ctx = test_context();
        let cmd = simple_cmd("readarray -d ':' -n 5 arr");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                // Should only set arr, not -d or -n values
                let state = env.get("arr");
                assert!(matches!(state, Some(VarState::Opaque)));
                assert!(env.get(":").is_none());
                assert!(env.get("5").is_none());
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn non_read_builtin_continues() {
        let ctx = test_context();
        let cmd = simple_cmd("echo hello");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {
                // Correctly continues
            }
            _ => panic!("Expected continue outcome"),
        }
    }

    #[test]
    fn read_with_multiple_vars_sets_all_opaque() {
        let ctx = test_context();
        let cmd = simple_cmd("read var1 var2 var3");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                assert!(matches!(env.get("var1"), Some(VarState::Opaque)));
                assert!(matches!(env.get("var2"), Some(VarState::Opaque)));
                assert!(matches!(env.get("var3"), Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn read_with_herestring_and_multiple_vars_all_opaque() {
        let ctx = test_context();
        let cmd = simple_cmd("read var1 var2 <<< 'hello world'");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                // With multiple vars, all should be opaque even with herestring
                assert!(matches!(env.get("var1"), Some(VarState::Opaque)));
                assert!(matches!(env.get("var2"), Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }

    #[test]
    fn mapfile_with_all_flag_types() {
        let ctx = test_context();
        // Test all flag types that take arguments for mapfile
        let cmd = simple_cmd("mapfile -d ':' -n 5 -O 0 -t -u 0 -C cmd -c 1 arr");
        let visitor = ReadBuiltinVisitor;

        let outcome = visitor.visit_simple_command(&ctx, &cmd);

        match outcome {
            VisitOutcome::Terminal { env, .. } => {
                // Should only set arr
                assert!(matches!(env.get("arr"), Some(VarState::Opaque)));
            }
            _ => panic!("Expected terminal outcome"),
        }
    }
}

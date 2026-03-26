// Visitor trait and concrete visitor implementations for the engine.

pub(crate) mod code_execution;
pub(crate) mod dynamic_parts;
pub(crate) mod function_call;
pub(crate) mod read_builtin;
pub(crate) mod rule_match;
pub(crate) mod wrapper_unwrap;

use crate::var_env::VarEnv;
use may_i_core::legacy::{Config, ContextFacts, Decision, EvalResult};
use may_i_shell_parser::{Command, SimpleCommand};

/// Maximum recursion depth for command substitution / eval / bash -c evaluation.
pub(crate) const MAX_EVAL_DEPTH: usize = 10;

/// Build an Ask result for unresolvable dynamic values.
/// `context` is a prefix like "Cannot statically analyse" or
/// "Command `foo` contains".
pub(crate) fn dynamic_ask(dynamic: &[String], context: &str) -> EvalResult {
    let mut seen = std::collections::HashSet::new();
    let parts: Vec<&str> = dynamic
        .iter()
        .filter(|p| seen.insert(p.as_str()))
        .map(|p| p.as_str())
        .collect();
    EvalResult::new(
        Decision::Ask,
        Some(format!(
            "{context} dynamic value{} that cannot be statically analysed: {}",
            if parts.len() == 1 { "" } else { "s" },
            parts.join(", "),
        )),
    )
}

/// Outcome of a visitor inspecting a resolved simple command.
#[derive(Debug)]
pub(crate) enum VisitOutcome {
    /// Terminal: return this result, skip remaining visitors.
    /// The `env` may differ from the input (e.g. `read` builtin updates variables).
    Terminal { result: EvalResult, env: VarEnv },
    /// This visitor doesn't handle the command; try the next one.
    Continue,
    /// Re-walk a different command (e.g. after unwrapping `eval`, `bash -c`,
    /// or wrapper commands). The walker will recursively walk the new command.
    Recurse {
        command: Command,
        env: VarEnv,
        context: ContextFacts,
    },
}

/// Context passed to visitors, providing read access to walker state.
pub(crate) struct VisitorContext<'a> {
    pub config: &'a Config,
    pub context: &'a ContextFacts,
    pub env: &'a VarEnv,
    pub depth: usize,
}

/// Trait for leaf-level command behaviors.
///
/// Each visitor inspects a fully-resolved `SimpleCommand` and returns a
/// `VisitOutcome` indicating whether it handled the command, wants to
/// pass, or wants the walker to recurse into a different command.
///
/// The walker calls visitors in order; the first non-`Continue` outcome wins.
pub(crate) trait CommandVisitor {
    /// Inspect a resolved simple command.
    ///
    /// Called after variable resolution and command-substitution resolution,
    /// so all resolvable parts are already literals or opaque.
    fn visit_simple_command(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> VisitOutcome {
        let _ = (ctx, resolved);
        VisitOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_ask_with_single_value() {
        let result = dynamic_ask(&["foo".to_string()], "Command contains");
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("Command contains"));
        assert!(reason.contains("foo"));
        assert!(reason.contains("dynamic value that cannot be statically analysed"));
        // Should not have 's' for plural
        assert!(!reason.contains("values"));
    }

    #[test]
    fn dynamic_ask_with_multiple_values() {
        let result = dynamic_ask(
            &["foo".to_string(), "bar".to_string()],
            "Cannot statically analyse",
        );
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("Cannot statically analyse"));
        assert!(reason.contains("foo"));
        assert!(reason.contains("bar"));
        // Should have 's' for plural
        assert!(reason.contains("dynamic values that cannot be statically analysed"));
    }

    #[test]
    fn dynamic_ask_deduplicates_duplicates() {
        let result = dynamic_ask(
            &["foo".to_string(), "foo".to_string(), "bar".to_string()],
            "Test",
        );
        let reason = result.reason.unwrap();
        // Should only list "foo" once
        let foo_count = reason.matches("foo").count();
        assert_eq!(foo_count, 1, "Should deduplicate 'foo'");
    }

    #[test]
    fn visit_outcome_terminal_variant() {
        let env = VarEnv::from_process_env();
        let result = EvalResult::new(Decision::Allow, None);
        let outcome = VisitOutcome::Terminal {
            result,
            env: env.clone(),
        };
        match outcome {
            VisitOutcome::Terminal { result, env: _ } => {
                assert_eq!(result.decision, Decision::Allow);
            }
            _ => panic!("Expected Terminal variant"),
        }
    }

    #[test]
    fn visit_outcome_continue_variant() {
        let outcome = VisitOutcome::Continue;
        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue variant"),
        }
    }

    #[test]
    fn visit_outcome_recurse_variant() {
        use may_i_shell_parser as parser;
        let env = VarEnv::from_process_env();
        let cmd = parser::parse("echo hello");
        let ctx = ContextFacts::default();
        let outcome = VisitOutcome::Recurse {
            command: cmd,
            env: env.clone(),
            context: ctx,
        };
        match outcome {
            VisitOutcome::Recurse {
                command: _,
                env: _,
                context: _,
            } => {}
            _ => panic!("Expected Recurse variant"),
        }
    }

    #[test]
    fn command_visitor_default_returns_continue() {
        struct TestVisitor;
        impl CommandVisitor for TestVisitor {}

        let config = Config::default();
        let context = ContextFacts::default();
        let env = VarEnv::from_process_env();
        let visitor_ctx = VisitorContext {
            config: &config,
            context: &context,
            env: &env,
            depth: 0,
        };
        // Create a simple command by parsing
        let cmd = match may_i_shell_parser::parse("ls") {
            Command::Simple(sc) => sc,
            _ => panic!("Expected simple command"),
        };

        let visitor = TestVisitor;
        let outcome = visitor.visit_simple_command(&visitor_ctx, &cmd);

        match outcome {
            VisitOutcome::Continue => {}
            _ => panic!("Expected Continue for default implementation"),
        }
    }

    #[test]
    fn visitor_context_holds_references() {
        let config = Config::default();
        let context = ContextFacts::default();
        let env = VarEnv::from_process_env();

        let ctx = VisitorContext {
            config: &config,
            context: &context,
            env: &env,
            depth: 5,
        };

        assert_eq!(ctx.depth, 5);
    }
}

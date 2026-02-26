// Visitor trait and concrete visitor implementations for the engine.

pub(crate) mod dynamic_parts;
pub(crate) mod code_execution;
pub(crate) mod function_call;
pub(crate) mod read_builtin;
pub(crate) mod wrapper_unwrap;
pub(crate) mod rule_match;

use may_i_core::{Config, EvalResult};
use may_i_shell_parser::{Command, SimpleCommand};
use crate::var_env::VarEnv;

/// Outcome of a visitor inspecting a resolved simple command.
pub(crate) enum VisitOutcome {
    /// Terminal: return this result, skip remaining visitors.
    /// The `env` may differ from the input (e.g. `read` builtin updates variables).
    Terminal { result: EvalResult, env: VarEnv },
    /// This visitor doesn't handle the command; try the next one.
    Continue,
    /// Re-walk a different command (e.g. after unwrapping `eval`, `bash -c`,
    /// or wrapper commands). The walker will recursively walk the new command.
    Recurse { command: Command, env: VarEnv },
}

/// Context passed to visitors, providing read access to walker state.
pub(crate) struct VisitorContext<'a> {
    pub config: &'a Config,
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
    fn visit_simple_command(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> VisitOutcome {
        let _ = (ctx, resolved);
        VisitOutcome::Continue
    }
}

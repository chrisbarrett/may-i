// Rule engine — R7, R8, R9
// Evaluates parsed commands against rules, handles wrappers and flag expansion.
// Walks the AST with a VarEnv to track variable safety through shell constructs.

pub(crate) mod annotate;
pub(crate) mod matcher;
pub(crate) mod visitors;
pub(crate) mod check;
pub(crate) mod var_env;

use visitors::{CommandVisitor, VisitOutcome, VisitorContext, MAX_EVAL_DEPTH, dynamic_ask};

use may_i_shell_parser::{self as parser, Command, SimpleCommand, Word};
use may_i_core::{Config, Decision, EvalResult};
use var_env::{
    VarEnv, VarState, resolve_word_with_var_env, resolve_simple_command_with_var_env,
};

pub use check::{run_checks, CheckResult};

/// Result of walking an AST node: the evaluation result and the updated VarEnv.
struct WalkResult {
    result: EvalResult,
    env: VarEnv,
}

impl WalkResult {
    /// For subprocess-like constructs (subshell, pipeline, background) that run
    /// in a child scope: env changes inside do not propagate back to the parent.
    fn with_parent_env(result: EvalResult, parent_env: &VarEnv) -> Self {
        WalkResult { result, env: parent_env.clone() }
    }
}

/// Aggregate multiple results: most restrictive decision wins.
fn aggregate_results(results: Vec<EvalResult>) -> EvalResult {
    debug_assert!(!results.is_empty(), "aggregate_results called with empty vec");
    results
        .into_iter()
        .max_by_key(|r| r.decision)
        .unwrap_or_else(|| EvalResult::new(Decision::Allow, None))
}

// ── AstWalker ──────────────────────────────────────────────────────

/// Walks a shell AST, threading VarEnv through control flow and evaluating
/// commands against rules.
struct AstWalker<'a> {
    config: &'a Config,
}

impl<'a> AstWalker<'a> {
    fn new(config: &'a Config) -> Self {
        Self { config }
    }

    fn walk(&self, cmd: &Command, env: &VarEnv) -> WalkResult {
        self.walk_with_depth(cmd, env, 0)
    }

    /// Dispatch a single visitor on a resolved command.
    /// Returns `Some(WalkResult)` if the visitor handled it, `None` if it passed.
    fn run_visitor(
        &self,
        visitor: &dyn CommandVisitor,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> Option<WalkResult> {
        match visitor.visit_simple_command(ctx, resolved) {
            VisitOutcome::Terminal { result, env } => Some(WalkResult { result, env }),
            VisitOutcome::Continue => None,
            VisitOutcome::Recurse { command, env } => {
                Some(self.walk_with_depth(&command, &env, ctx.depth + 1))
            }
        }
    }

    /// Run the visitor chain on a resolved command. First non-Continue outcome wins.
    /// The chain always terminates: RuleMatchVisitor is the final catch-all.
    fn run_visitors(
        &self,
        ctx: &VisitorContext,
        resolved: &SimpleCommand,
    ) -> Option<WalkResult> {
        let visitors: &[&dyn CommandVisitor] = &[
            &visitors::read_builtin::ReadBuiltinVisitor,
            &visitors::dynamic_parts::DynamicPartsVisitor,
            &visitors::code_execution::CodeExecutionVisitor,
            &visitors::function_call::FunctionCallVisitor,
            &visitors::wrapper_unwrap::WrapperUnwrapVisitor,
            &visitors::rule_match::RuleMatchVisitor,
        ];
        for visitor in visitors {
            if let Some(walk) = self.run_visitor(*visitor, ctx, resolved) {
                return Some(walk);
            }
        }
        None
    }

    fn walk_with_depth(&self, cmd: &Command, env: &VarEnv, depth: usize) -> WalkResult {
        match cmd {
            Command::Simple(sc) => self.walk_simple_command(sc, env, depth),

            Command::Assignment(a) => {
                let mut new_env = env.clone();
                let state = self.evaluate_assignment_value(&a.value, env, depth);
                new_env.set(a.name.clone(), state);
                WalkResult {
                    result: EvalResult::new(Decision::Allow, None),
                    env: new_env,
                }
            }

            Command::Sequence(cmds) => {
                let mut current_env = env.clone();
                let mut results = Vec::new();
                for c in cmds {
                    let walk = self.walk_with_depth(c, &current_env, depth);
                    if walk.result.decision == Decision::Deny {
                        return WalkResult {
                            result: walk.result,
                            env: walk.env,
                        };
                    }
                    results.push(walk.result);
                    current_env = walk.env;
                }
                WalkResult {
                    result: aggregate_results(results),
                    env: current_env,
                }
            }

            Command::And(a, b) | Command::Or(a, b) => {
                let walk_a = self.walk_with_depth(a, env, depth);
                if walk_a.result.decision == Decision::Deny {
                    return walk_a;
                }
                let walk_b = self.walk_with_depth(b, &walk_a.env, depth);
                let merged = VarEnv::merge_branches(env, &[walk_a.env, walk_b.env.clone()]);
                WalkResult {
                    result: aggregate_results(vec![walk_a.result, walk_b.result]),
                    env: merged,
                }
            }

            Command::Pipeline(cmds) => {
                let mut results = Vec::new();
                for c in cmds {
                    let walk = self.walk_with_depth(c, env, depth);
                    if walk.result.decision == Decision::Deny {
                        return WalkResult::with_parent_env(walk.result, env);
                    }
                    results.push(walk.result);
                }
                WalkResult::with_parent_env(aggregate_results(results), env)
            }

            Command::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let walk_cond = self.walk_with_depth(condition, env, depth);
                let mut results = vec![walk_cond.result];
                let env_after_cond = &walk_cond.env;

                let walk_then = self.walk_with_depth(then_branch, env_after_cond, depth);
                results.push(walk_then.result);
                let mut branch_envs = vec![walk_then.env];

                for (elif_cond, elif_body) in elif_branches {
                    let wc = self.walk_with_depth(elif_cond, env_after_cond, depth);
                    let wb = self.walk_with_depth(elif_body, &wc.env, depth);
                    results.push(wc.result);
                    results.push(wb.result);
                    branch_envs.push(wb.env);
                }

                if let Some(else_b) = else_branch {
                    let we = self.walk_with_depth(else_b, env_after_cond, depth);
                    results.push(we.result);
                    branch_envs.push(we.env);
                } else {
                    branch_envs.push(env_after_cond.clone());
                }

                let merged = VarEnv::merge_branches(env_after_cond, &branch_envs);
                WalkResult {
                    result: aggregate_results(results),
                    env: merged,
                }
            }

            Command::For { var, words, body } => self.walk_for_loop(var, words, body, env, depth),

            Command::Loop { condition, body, .. } => {
                let walk_cond = self.walk_with_depth(condition, env, depth);
                let walk_body = self.walk_with_depth(body, &walk_cond.env, depth);
                let merged = VarEnv::merge_branches(env, &[env.clone(), walk_body.env]);
                WalkResult {
                    result: aggregate_results(vec![walk_cond.result, walk_body.result]),
                    env: merged,
                }
            }

            Command::Subshell(c) => {
                let walk = self.walk_with_depth(c, env, depth);
                WalkResult::with_parent_env(walk.result, env)
            }

            Command::BraceGroup(c) => {
                self.walk_with_depth(c, env, depth)
            }

            Command::Background(c) => {
                let walk = self.walk_with_depth(c, env, depth);
                WalkResult::with_parent_env(walk.result, env)
            }

            Command::Case { word, arms, .. } => {
                let resolved_word = resolve_word_with_var_env(word, env);
                if resolved_word.has_dynamic_parts() {
                    return WalkResult {
                        result: dynamic_ask(&resolved_word.dynamic_parts(), "Cannot statically analyse"),
                        env: env.clone(),
                    };
                }

                let mut results = Vec::new();
                let mut branch_envs = Vec::new();
                for arm in arms {
                    if let Some(body) = &arm.body {
                        let walk = self.walk_with_depth(body, env, depth);
                        results.push(walk.result);
                        branch_envs.push(walk.env);
                    }
                }
                branch_envs.push(env.clone());
                let merged = VarEnv::merge_branches(env, &branch_envs);
                WalkResult {
                    result: aggregate_results(results),
                    env: merged,
                }
            }

            Command::FunctionDef { name, body } => {
                let mut new_env = env.clone();
                new_env.set_fn(name.clone(), *body.clone());
                WalkResult {
                    result: EvalResult::new(Decision::Allow, None),
                    env: new_env,
                }
            }

            Command::Redirected { command, .. } => {
                self.walk_with_depth(command, env, depth)
            }
        }
    }

    fn walk_for_loop(
        &self,
        var: &str,
        words: &[Word],
        body: &Command,
        env: &VarEnv,
        depth: usize,
    ) -> WalkResult {
        let resolved_words: Vec<Word> = words.iter().map(|w| resolve_word_with_var_env(w, env)).collect();

        if resolved_words.iter().all(|w| w.is_literal()) {
            let literals: Vec<String> = resolved_words.iter().map(|w| w.to_str()).collect();
            if literals.is_empty() {
                return WalkResult {
                    result: EvalResult::new(Decision::Allow, None),
                    env: env.clone(),
                };
            }

            let mut results = Vec::new();
            let mut body_envs = Vec::new();
            for val in &literals {
                let mut loop_env = env.clone();
                loop_env.set(var.to_string(), VarState::Known(val.clone()));
                let walk = self.walk_with_depth(body, &loop_env, depth);
                if walk.result.decision == Decision::Deny {
                    return WalkResult {
                        result: walk.result,
                        env: env.clone(),
                    };
                }
                results.push(walk.result);
                body_envs.push(walk.env);
            }

            let mut merged = VarEnv::merge_branches(env, &body_envs);
            merged.set(var.to_string(), VarState::Opaque);
            return WalkResult {
                result: aggregate_results(results),
                env: merged,
            };
        }

        if !resolved_words.iter().any(|w| w.has_dynamic_parts()) {
            let mut loop_env = env.clone();
            loop_env.set(var.to_string(), VarState::Opaque);
            let walk = self.walk_with_depth(body, &loop_env, depth);
            let merged = VarEnv::merge_branches(env, &[env.clone(), walk.env]);
            return WalkResult {
                result: walk.result,
                env: merged,
            };
        }

        let dynamic: Vec<String> = resolved_words.iter().flat_map(|w| w.dynamic_parts()).collect();
        WalkResult {
            result: dynamic_ask(&dynamic, "Cannot statically analyse"),
            env: env.clone(),
        }
    }

    fn evaluate_assignment_value(&self, value: &Word, env: &VarEnv, depth: usize) -> VarState {
        let resolved = resolve_word_with_var_env(&self.resolve_command_substitutions(value, env, depth), env);
        if resolved.has_dynamic_parts() {
            VarState::Unsafe
        } else if resolved.is_literal() {
            VarState::Known(resolved.to_str())
        } else {
            VarState::Opaque
        }
    }

    fn resolve_command_substitutions(&self, word: &Word, env: &VarEnv, depth: usize) -> Word {
        Word {
            parts: self.resolve_cmd_sub_parts(&word.parts, env, depth),
        }
    }

    fn resolve_cmd_sub_parts(
        &self,
        parts: &[parser::WordPart],
        env: &VarEnv,
        depth: usize,
    ) -> Vec<parser::WordPart> {
        if depth >= MAX_EVAL_DEPTH {
            return parts.to_vec();
        }
        parts
            .iter()
            .map(|part| match part {
                parser::WordPart::CommandSubstitution(cmd_str)
                | parser::WordPart::Backtick(cmd_str) => {
                    let inner_ast = parser::parse(cmd_str);
                    let inner_result = self.walk_with_depth(&inner_ast, env, depth + 1);
                    if inner_result.result.decision == Decision::Allow {
                        parser::WordPart::Opaque(format!("$({})", parser::abbreviate(cmd_str)))
                    } else {
                        part.clone()
                    }
                }
                parser::WordPart::ProcessSubstitution { direction, command } => {
                    let inner_ast = parser::parse(command);
                    let inner_result = self.walk_with_depth(&inner_ast, env, depth + 1);
                    if inner_result.result.decision == Decision::Allow {
                        let sigil = match direction {
                            parser::ProcessDirection::Input => '<',
                            parser::ProcessDirection::Output => '>',
                        };
                        parser::WordPart::Opaque(format!("{}({})", sigil, parser::abbreviate(command)))
                    } else {
                        part.clone()
                    }
                }
                parser::WordPart::Arithmetic(expr) => {
                    if is_arithmetic_safe(expr, env) {
                        parser::WordPart::Opaque(format!("$(({})", parser::abbreviate(expr)))
                    } else {
                        part.clone()
                    }
                }
                parser::WordPart::DoubleQuoted(inner) => {
                    parser::WordPart::DoubleQuoted(self.resolve_cmd_sub_parts(inner, env, depth))
                }
                _ => part.clone(),
            })
            .collect()
    }

    fn walk_simple_command(&self, sc: &SimpleCommand, env: &VarEnv, depth: usize) -> WalkResult {
        let mut new_env = env.clone();

        // Process inline assignments (FOO=bar cmd args)
        for a in &sc.assignments {
            let state = self.evaluate_assignment_value(&a.value, &new_env, depth);
            new_env.set(a.name.clone(), state);
        }

        // If no command words, this is an assignment-only command
        if sc.words.is_empty() {
            return WalkResult {
                result: EvalResult::new(Decision::Allow, None),
                env: new_env,
            };
        }

        // Resolve command substitutions first, then resolve variables
        let with_cmd_subs = sc.map_words(|w| self.resolve_command_substitutions(w, &new_env, depth));
        let resolved = resolve_simple_command_with_var_env(&with_cmd_subs, &new_env);

        // Run visitor chain (terminates with rule matching — always produces a result)
        let ctx = VisitorContext { config: self.config, env: &new_env, depth };
        self.run_visitors(&ctx, &resolved)
            .unwrap_or_else(|| unreachable!("RuleMatchVisitor always returns Terminal"))
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Evaluate a shell command string against the config.
pub fn evaluate(input: &str, config: &Config) -> EvalResult {
    let ast = parser::parse(input);
    let env = VarEnv::from_process_env();
    AstWalker::new(config).walk(&ast, &env).result
}

/// Evaluate with a specific VarEnv (for testing).
#[cfg(test)]
fn evaluate_with_env(input: &str, config: &Config, env: &VarEnv) -> EvalResult {
    let ast = parser::parse(input);
    AstWalker::new(config).walk(&ast, env).result
}

// ── Standalone helpers ─────────────────────────────────────────────

/// Check if an arithmetic expression is safe: all variable references resolve to safe vars.
fn is_arithmetic_safe(expr: &str, env: &VarEnv) -> bool {
    let mut i = 0;
    let bytes = expr.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'{' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'}' {
                    i += 1;
                }
                let name = &expr[start..i];
                if !name.is_empty() && !env.is_safe(name) {
                    return false;
                }
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let name = &expr[start..i];
                if !name.is_empty() && !env.is_safe(name) {
                    return false;
                }
            }
        } else if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            let name = &expr[start..i];
            if !env.is_safe(name) {
                return false;
            }
        } else {
            i += 1;
        }
    }
    true
}

#[cfg(test)]
mod engine_tests;

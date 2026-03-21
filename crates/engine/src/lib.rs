// Rule engine — evaluates against unified rule DSL with recursive evaluation

pub(crate) mod annotate;
pub(crate) mod check;
pub(crate) mod matcher;
pub(crate) mod var_env;
pub(crate) mod visitors;

// v2 evaluator for unified rule DSL
pub mod v2;

use visitors::{CommandVisitor, MAX_EVAL_DEPTH, VisitOutcome, VisitorContext, dynamic_ask};

use may_i_core::{Config, ContextFacts, Decision, EvalResult};
use may_i_shell_parser::{self as parser, Command, SimpleCommand, Word};
use var_env::{VarEnv, VarState, resolve_simple_command_with_var_env, resolve_word_with_var_env};

pub use check::{CheckResult, run_checks};

// Re-export v2 items
pub use v2::{
    DEFAULT_RECURSION_LIMIT, EvalContext, Evaluator, PredicateResult, TraceBuilder, TraceEntry,
    evaluate_v2,
};

/// Result of walking an AST node: the evaluation result and the updated VarEnv.
struct WalkResult {
    result: EvalResult,
    env: VarEnv,
}

impl WalkResult {
    /// For subprocess-like constructs (subshell, pipeline, background) that run
    /// in a child scope: env changes inside do not propagate back to the parent.
    fn with_parent_env(result: EvalResult, parent_env: &VarEnv) -> Self {
        WalkResult {
            result,
            env: parent_env.clone(),
        }
    }
}

/// Aggregate multiple results: most restrictive decision wins.
fn aggregate_results(results: Vec<EvalResult>) -> EvalResult {
    debug_assert!(
        !results.is_empty(),
        "aggregate_results called with empty vec"
    );
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

    fn walk(&self, cmd: &Command, env: &VarEnv, context: &ContextFacts) -> WalkResult {
        self.walk_with_depth(cmd, env, context, 0)
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
            VisitOutcome::Recurse {
                command,
                env,
                context,
            } => Some(self.walk_with_depth(&command, &env, &context, ctx.depth + 1)),
        }
    }

    /// Run the visitor chain on a resolved command. First non-Continue outcome wins.
    /// The chain always terminates: RuleMatchVisitor is the final catch-all.
    fn run_visitors(&self, ctx: &VisitorContext, resolved: &SimpleCommand) -> Option<WalkResult> {
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

    fn walk_with_depth(
        &self,
        cmd: &Command,
        env: &VarEnv,
        context: &ContextFacts,
        depth: usize,
    ) -> WalkResult {
        match cmd {
            Command::Simple(sc) => self.walk_simple_command(sc, env, context, depth),

            Command::Assignment(a) => {
                let mut new_env = env.clone();
                let state = self.evaluate_assignment_value(&a.value, env, context, depth);
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
                    let walk = self.walk_with_depth(c, &current_env, context, depth);
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
                let walk_a = self.walk_with_depth(a, env, context, depth);
                if walk_a.result.decision == Decision::Deny {
                    return walk_a;
                }
                let walk_b = self.walk_with_depth(b, &walk_a.env, context, depth);
                let merged = VarEnv::merge_branches(env, &[walk_a.env, walk_b.env.clone()]);
                WalkResult {
                    result: aggregate_results(vec![walk_a.result, walk_b.result]),
                    env: merged,
                }
            }

            Command::Pipeline(cmds) => {
                let mut results = Vec::new();
                for c in cmds {
                    let walk = self.walk_with_depth(c, env, context, depth);
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
                let walk_cond = self.walk_with_depth(condition, env, context, depth);
                let mut results = vec![walk_cond.result];
                let env_after_cond = &walk_cond.env;

                let walk_then = self.walk_with_depth(then_branch, env_after_cond, context, depth);
                results.push(walk_then.result);
                let mut branch_envs = vec![walk_then.env];

                for (elif_cond, elif_body) in elif_branches {
                    let wc = self.walk_with_depth(elif_cond, env_after_cond, context, depth);
                    let wb = self.walk_with_depth(elif_body, &wc.env, context, depth);
                    results.push(wc.result);
                    results.push(wb.result);
                    branch_envs.push(wb.env);
                }

                if let Some(else_b) = else_branch {
                    let we = self.walk_with_depth(else_b, env_after_cond, context, depth);
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

            Command::For { var, words, body } => {
                self.walk_for_loop(var, words, body, env, context, depth)
            }

            Command::Loop {
                condition, body, ..
            } => {
                let walk_cond = self.walk_with_depth(condition, env, context, depth);
                let walk_body = self.walk_with_depth(body, &walk_cond.env, context, depth);
                let merged = VarEnv::merge_branches(env, &[env.clone(), walk_body.env]);
                WalkResult {
                    result: aggregate_results(vec![walk_cond.result, walk_body.result]),
                    env: merged,
                }
            }

            Command::Subshell(c) => {
                let walk = self.walk_with_depth(c, env, context, depth);
                WalkResult::with_parent_env(walk.result, env)
            }

            Command::BraceGroup(c) => self.walk_with_depth(c, env, context, depth),

            Command::Background(c) => {
                let walk = self.walk_with_depth(c, env, context, depth);
                WalkResult::with_parent_env(walk.result, env)
            }

            Command::Case { word, arms, .. } => {
                let resolved_word = resolve_word_with_var_env(word, env);
                if resolved_word.has_dynamic_parts() {
                    return WalkResult {
                        result: dynamic_ask(
                            &resolved_word.dynamic_parts(),
                            "Cannot statically analyse",
                        ),
                        env: env.clone(),
                    };
                }

                let mut results = Vec::new();
                let mut branch_envs = Vec::new();
                for arm in arms {
                    if let Some(body) = &arm.body {
                        let walk = self.walk_with_depth(body, env, context, depth);
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
                self.walk_with_depth(command, env, context, depth)
            }
        }
    }

    fn walk_for_loop(
        &self,
        var: &str,
        words: &[Word],
        body: &Command,
        env: &VarEnv,
        context: &ContextFacts,
        depth: usize,
    ) -> WalkResult {
        let resolved_words: Vec<Word> = words
            .iter()
            .map(|w| resolve_word_with_var_env(w, env))
            .collect();

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
                let walk = self.walk_with_depth(body, &loop_env, context, depth);
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
            let walk = self.walk_with_depth(body, &loop_env, context, depth);
            let merged = VarEnv::merge_branches(env, &[env.clone(), walk.env]);
            return WalkResult {
                result: walk.result,
                env: merged,
            };
        }

        let dynamic: Vec<String> = resolved_words
            .iter()
            .flat_map(|w| w.dynamic_parts())
            .collect();
        WalkResult {
            result: dynamic_ask(&dynamic, "Cannot statically analyse"),
            env: env.clone(),
        }
    }

    fn evaluate_assignment_value(
        &self,
        value: &Word,
        env: &VarEnv,
        context: &ContextFacts,
        depth: usize,
    ) -> VarState {
        let resolved = resolve_word_with_var_env(
            &self.resolve_command_substitutions(value, env, context, depth),
            env,
        );
        if resolved.has_dynamic_parts() {
            VarState::Unsafe
        } else if resolved.is_literal() {
            VarState::Known(resolved.to_str())
        } else {
            VarState::Opaque
        }
    }

    fn resolve_command_substitutions(
        &self,
        word: &Word,
        env: &VarEnv,
        context: &ContextFacts,
        depth: usize,
    ) -> Word {
        Word {
            parts: self.resolve_cmd_sub_parts(&word.parts, env, context, depth),
        }
    }

    fn resolve_cmd_sub_parts(
        &self,
        parts: &[parser::WordPart],
        env: &VarEnv,
        context: &ContextFacts,
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
                    let inner_result = self.walk_with_depth(&inner_ast, env, context, depth + 1);
                    if inner_result.result.decision == Decision::Allow {
                        parser::WordPart::Opaque(format!("$({})", parser::abbreviate(cmd_str)))
                    } else {
                        part.clone()
                    }
                }
                parser::WordPart::ProcessSubstitution { direction, command } => {
                    let inner_ast = parser::parse(command);
                    let inner_result = self.walk_with_depth(&inner_ast, env, context, depth + 1);
                    if inner_result.result.decision == Decision::Allow {
                        let sigil = match direction {
                            parser::ProcessDirection::Input => '<',
                            parser::ProcessDirection::Output => '>',
                        };
                        parser::WordPart::Opaque(format!(
                            "{}({})",
                            sigil,
                            parser::abbreviate(command)
                        ))
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
                parser::WordPart::DoubleQuoted(inner) => parser::WordPart::DoubleQuoted(
                    self.resolve_cmd_sub_parts(inner, env, context, depth),
                ),
                _ => part.clone(),
            })
            .collect()
    }

    fn walk_simple_command(
        &self,
        sc: &SimpleCommand,
        env: &VarEnv,
        context: &ContextFacts,
        depth: usize,
    ) -> WalkResult {
        let mut new_env = env.clone();

        // Process inline assignments (FOO=bar cmd args)
        for a in &sc.assignments {
            let state = self.evaluate_assignment_value(&a.value, &new_env, context, depth);
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
        let with_cmd_subs =
            sc.map_words(|w| self.resolve_command_substitutions(w, &new_env, context, depth));
        let resolved = resolve_simple_command_with_var_env(&with_cmd_subs, &new_env);

        // Run visitor chain (terminates with rule matching — always produces a result)
        let ctx = VisitorContext {
            config: self.config,
            context,
            env: &new_env,
            depth,
        };
        self.run_visitors(&ctx, &resolved)
            .unwrap_or_else(|| unreachable!("RuleMatchVisitor always returns Terminal"))
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Evaluate a shell command string against the config.
pub fn evaluate(input: &str, config: &Config) -> EvalResult {
    evaluate_with_context(input, config, &ContextFacts::default())
}

pub fn evaluate_with_context(input: &str, config: &Config, context: &ContextFacts) -> EvalResult {
    let ast = parser::parse(input);

    // Seed environment from process, then ensure any vars listed in
    // `(safe-env-vars ...)` are present as safe (opaque) even if absent.
    let mut env = VarEnv::from_process_env();
    if !config.security.safe_env_vars.is_empty() {
        for name in &config.security.safe_env_vars {
            if env.get(name).is_none() {
                env.set(name.clone(), VarState::Opaque);
            }
        }
    }

    AstWalker::new(config).walk(&ast, &env, context).result
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
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = &expr[start..i];
                if !name.is_empty() && !env.is_safe(name) {
                    return false;
                }
            }
        } else if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
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
mod lib_tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::{CommandMatcher, Decision, Effect, EvalResult, Rule, RuleBody};

    fn empty_config() -> Config {
        Config::default()
    }

    fn allow_config() -> Config {
        Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("echo".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: None,
                    },
                },
                checks: vec![],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        }
    }

    fn deny_config() -> Config {
        Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("rm".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Deny,
                        reason: Some("dangerous".into()),
                    },
                },
                checks: vec![],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        }
    }

    #[test]
    fn test_evaluate_simple_allow() {
        let config = allow_config();
        let result = evaluate("echo hello", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_simple_deny() {
        let config = deny_config();
        let result = evaluate("rm -rf /", &config);
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_ref().unwrap().contains("dangerous"));
    }

    #[test]
    fn test_evaluate_no_matching_rule_ask() {
        let config = empty_config();
        let result = evaluate("unknown-cmd", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_with_context_empty() {
        let config = allow_config();
        let context = ContextFacts::default();
        let result = evaluate_with_context("echo hello", &config, &context);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_assignment_command() {
        let config = allow_config();
        let result = evaluate("FOO=bar echo hello", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_sequence_commands() {
        let config = allow_config();
        let result = evaluate("echo hello; echo world", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_pipeline() {
        let config = allow_config();
        let result = evaluate("echo hello | cat", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_subshell() {
        let config = allow_config();
        let result = evaluate("(echo hello)", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_background() {
        let config = allow_config();
        let result = evaluate("echo hello &", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_if_statement_with_echo_condition() {
        // Test that if statement structure is handled correctly
        // The condition command (echo x) is evaluated, then body
        let config = allow_config();
        let result = evaluate("if echo x; then echo hello; fi", &config);
        // echo is allowed, so both condition and body are allowed
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_while_loop_with_echo() {
        let config = allow_config();
        let result = evaluate("while echo x; do echo hello; done", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_for_loop() {
        let config = allow_config();
        let result = evaluate("for x in a b c; do echo $x; done", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_case_statement() {
        let config = allow_config();
        let result = evaluate("case x in x) echo hello ;; esac", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_function_definition() {
        let config = allow_config();
        let result = evaluate("myfunc() { echo hello; }", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_and_list() {
        let config = allow_config();
        let result = evaluate("echo hello && echo world", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_or_list() {
        let config = allow_config();
        let result = evaluate("echo hello || echo world", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_brace_group() {
        let config = allow_config();
        let result = evaluate("{ echo hello; echo world; }", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_redirected_command() {
        let config = allow_config();
        let result = evaluate("echo hello > /tmp/test.txt", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_elif_branches() {
        let config = allow_config();
        let result = evaluate(
            "if echo x; then echo a; elif echo y; then echo hello; fi",
            &config,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_until_loop_with_echo() {
        let config = allow_config();
        let result = evaluate("until echo x; do echo hello; done", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_aggregate_results_single() {
        let results = vec![EvalResult::new(Decision::Allow, None)];
        let result = aggregate_results(results);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_is_arithmetic_safe_empty() {
        let env = VarEnv::from_process_env();
        assert!(is_arithmetic_safe("", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_literal() {
        let env = VarEnv::from_process_env();
        assert!(is_arithmetic_safe("42", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_simple_var() {
        let mut env = VarEnv::from_process_env();
        env.set(
            "HOME".to_string(),
            VarState::Known("/home/user".to_string()),
        );
        assert!(is_arithmetic_safe("$HOME", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_braced_var() {
        let mut env = VarEnv::from_process_env();
        env.set(
            "HOME".to_string(),
            VarState::Known("/home/user".to_string()),
        );
        assert!(is_arithmetic_safe("${HOME}", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_unsafe_var() {
        let env = VarEnv::from_process_env();
        assert!(!is_arithmetic_safe("$UNKNOWN_VAR_NOT_IN_ENV", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_mixed() {
        let mut env = VarEnv::from_process_env();
        env.set("X".to_string(), VarState::Known("1".to_string()));
        assert!(is_arithmetic_safe("$X + 1", &env));
    }

    #[test]
    fn test_walk_result_with_parent_env() {
        let parent_env = VarEnv::from_process_env();
        let result = EvalResult::new(Decision::Allow, None);
        let walk_result = WalkResult::with_parent_env(result, &parent_env);
        assert_eq!(walk_result.result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_empty_input() {
        let config = empty_config();
        let result = evaluate("", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_whitespace_only() {
        let config = empty_config();
        let result = evaluate("   ", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_assignment_only() {
        let config = empty_config();
        let result = evaluate("FOO=bar", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_else_branch() {
        let config = allow_config();
        let result = evaluate("if echo x; then echo skip; else echo hello; fi", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_no_else_branch_empty_config() {
        // When condition is not in config, returns Ask
        let config = empty_config();
        let result = evaluate("if echo x; then echo hello; fi", &config);
        // echo not in config, so Ask
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_empty_for_loop() {
        let config = empty_config();
        let result = evaluate("for x in; do echo $x; done", &config);
        // No iterations, no commands evaluated
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_sequence_with_deny() {
        // Create a config that denies 'rm'
        let config = deny_config();
        // Sequence where second command is denied
        let result = evaluate("echo hello; rm -rf /", &config);
        // Should return Deny because rm is in the sequence
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_pipeline_returns_aggregate() {
        // Pipeline returns aggregated result
        let config = allow_config();
        let result = evaluate("echo hello | cat | wc -l", &config);
        // cat and wc are not in config, so should ask
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_deny_in_and_list() {
        let config = deny_config();
        let result = evaluate("rm -rf / && echo hello", &config);
        // First command denies, so whole and-list denies
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_or_list() {
        let config = deny_config();
        let result = evaluate("rm -rf / || echo hello", &config);
        // First command denies
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_background_with_deny() {
        let config = deny_config();
        let result = evaluate("rm -rf / &", &config);
        // Background still evaluates the command
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_subshell_with_deny() {
        let config = deny_config();
        let result = evaluate("(rm -rf /)", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_if_body() {
        let config = deny_config();
        let result = evaluate("if echo x; then rm -rf /; fi", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_while_body() {
        let config = deny_config();
        let result = evaluate("while echo x; do rm -rf /; done", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_for_body() {
        let config = deny_config();
        let result = evaluate("for x in a; do rm -rf /; done", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_case_body() {
        let config = deny_config();
        let result = evaluate("case x in x) rm -rf / ;; esac", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_function_body() {
        let config = deny_config();
        let result = evaluate("myfunc() { rm -rf /; }; myfunc", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_deny_in_brace_group() {
        let config = deny_config();
        let result = evaluate("{ rm -rf /; }", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_is_arithmetic_safe_variable_in_expression() {
        let mut env = VarEnv::from_process_env();
        env.set("COUNT".to_string(), VarState::Known("5".to_string()));
        // Variable used in arithmetic expression
        assert!(is_arithmetic_safe("$COUNT + 1", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_unsafe_variable() {
        let env = VarEnv::from_process_env();
        // Variable not in env is unsafe
        assert!(!is_arithmetic_safe("$UNSAFE_VAR + 1", &env));
    }

    #[test]
    fn test_is_arithmetic_safe_bare_variable_name() {
        let mut env = VarEnv::from_process_env();
        env.set("x".to_string(), VarState::Known("1".to_string()));
        env.set("y".to_string(), VarState::Known("2".to_string()));
        // Bare variable names (without $) should also be checked
        assert!(is_arithmetic_safe("x + y", &env));
    }
}

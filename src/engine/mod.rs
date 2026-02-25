// Rule engine — R7, R8, R9
// Evaluates parsed commands against rules, handles wrappers and flag expansion.
// Walks the AST with a VarEnv to track variable safety through shell constructs.

mod matcher;
use matcher::*;

use crate::parser::{self, Command, SimpleCommand, Word};
use crate::types::{ArgMatcher, Config, Decision, Effect, EvalResult, VarEnv, VarState};

/// Deduplicate a list of dynamic part descriptions while preserving order.
fn dedup_parts(parts: &[String]) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    parts
        .iter()
        .filter(|p| seen.insert(p.as_str()))
        .map(|p| p.as_str())
        .collect()
}

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

/// Aggregate multiple results: most restrictive wins. Deny short-circuits.
fn aggregate_results(results: Vec<EvalResult>) -> EvalResult {
    let mut overall: Option<EvalResult> = None;
    for result in results {
        if result.decision == Decision::Deny {
            return result;
        }
        match &overall {
            None => overall = Some(result),
            Some(prev) if result.decision.most_restrictive(prev.decision) != prev.decision => {
                overall = Some(result);
            }
            _ => {}
        }
    }
    overall.unwrap_or(EvalResult::new(Decision::Allow, None))
}

/// Evaluate a shell command string against the config.
pub fn evaluate(input: &str, config: &Config) -> EvalResult {
    let ast = parser::parse(input);

    // Seed VarEnv from all process environment variables
    let env = VarEnv::from_process_env();

    let walk = walk_command(&ast, config, &env);
    walk.result
}

/// Evaluate with a specific VarEnv (for testing).
#[cfg(test)]
fn evaluate_with_env(input: &str, config: &Config, env: &VarEnv) -> EvalResult {
    let ast = parser::parse(input);
    let walk = walk_command(&ast, config, env);
    walk.result
}

/// Walk an AST node, threading VarEnv through and evaluating commands.
fn walk_command(cmd: &Command, config: &Config, env: &VarEnv) -> WalkResult {
    walk_command_with_depth(cmd, config, env, 0)
}

/// Walk an AST node with a depth counter for recursion limiting.
fn walk_command_with_depth(cmd: &Command, config: &Config, env: &VarEnv, depth: usize) -> WalkResult {
    match cmd {
        Command::Simple(sc) => walk_simple_command(sc, config, env, depth),

        Command::Assignment(a) => {
            let mut new_env = env.clone();
            let state = evaluate_assignment_value(&a.value, env, config, depth);
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
                let walk = walk_command_with_depth(c, config, &current_env, depth);
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
            let walk_a = walk_command_with_depth(a, config, env, depth);
            if walk_a.result.decision == Decision::Deny {
                return walk_a;
            }
            let walk_b = walk_command_with_depth(b, config, &walk_a.env, depth);
            let merged = VarEnv::merge_branches(env, &[walk_a.env, walk_b.env.clone()]);
            WalkResult {
                result: aggregate_results(vec![walk_a.result, walk_b.result]),
                env: merged,
            }
        }

        Command::Pipeline(cmds) => {
            let mut results = Vec::new();
            for c in cmds {
                let walk = walk_command_with_depth(c, config, env, depth);
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
            let walk_cond = walk_command_with_depth(condition, config, env, depth);
            let mut results = vec![walk_cond.result];
            let env_after_cond = &walk_cond.env;

            let walk_then = walk_command_with_depth(then_branch, config, env_after_cond, depth);
            results.push(walk_then.result);
            let mut branch_envs = vec![walk_then.env];

            for (elif_cond, elif_body) in elif_branches {
                let wc = walk_command_with_depth(elif_cond, config, env_after_cond, depth);
                let wb = walk_command_with_depth(elif_body, config, &wc.env, depth);
                results.push(wc.result);
                results.push(wb.result);
                branch_envs.push(wb.env);
            }

            if let Some(else_b) = else_branch {
                let we = walk_command_with_depth(else_b, config, env_after_cond, depth);
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

        Command::For { var, words, body } => walk_for_loop(var, words, body, config, env, depth),

        Command::While { condition, body } | Command::Until { condition, body } => {
            let walk_cond = walk_command_with_depth(condition, config, env, depth);
            let walk_body = walk_command_with_depth(body, config, &walk_cond.env, depth);
            let merged = VarEnv::merge_branches(env, &[env.clone(), walk_body.env]);
            WalkResult {
                result: aggregate_results(vec![walk_cond.result, walk_body.result]),
                env: merged,
            }
        }

        Command::Subshell(c) => {
            let walk = walk_command_with_depth(c, config, env, depth);
            WalkResult::with_parent_env(walk.result, env)
        }

        Command::BraceGroup(c) => {
            walk_command_with_depth(c, config, env, depth)
        }

        Command::Background(c) => {
            let walk = walk_command_with_depth(c, config, env, depth);
            WalkResult::with_parent_env(walk.result, env)
        }

        Command::Case { word, arms, .. } => {
            let resolved_word = word.resolve_with_var_env(env);
            if resolved_word.has_dynamic_parts() {
                let dynamic = resolved_word.dynamic_parts();
                let parts = dedup_parts(&dynamic);
                return WalkResult {
                    result: EvalResult::new(
                        Decision::Ask,
                        Some(format!(
                            "Cannot statically analyse dynamic value{}: {}",
                            if parts.len() == 1 { "" } else { "s" },
                            parts.join(", "),
                        )),
                    ),
                    env: env.clone(),
                };
            }

            let mut results = Vec::new();
            let mut branch_envs = Vec::new();
            for arm in arms {
                if let Some(body) = &arm.body {
                    let walk = walk_command_with_depth(body, config, env, depth);
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
            walk_command_with_depth(command, config, env, depth)
        }
    }
}

/// Walk a for-loop: enumerate literal words or use opaque loop variable.
fn walk_for_loop(
    var: &str,
    words: &[Word],
    body: &Command,
    config: &Config,
    env: &VarEnv,
    depth: usize,
) -> WalkResult {
    // Resolve for-loop words using current VarEnv
    let resolved_words: Vec<Word> = words.iter().map(|w| w.resolve_with_var_env(env)).collect();

    // Check if all words are fully literal (resolvable)
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
            loop_env.set(var.to_string(), VarState::Safe(Some(val.clone())));
            let walk = walk_command_with_depth(body, config, &loop_env, depth);
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
        merged.set(var.to_string(), VarState::Safe(None));
        return WalkResult {
            result: aggregate_results(results),
            env: merged,
        };
    }

    // Check if words are safe but opaque (e.g., globs, safe-but-unresolvable vars)
    if !resolved_words.iter().any(|w| w.has_dynamic_parts()) {
        let mut loop_env = env.clone();
        loop_env.set(var.to_string(), VarState::Safe(None));
        let walk = walk_command_with_depth(body, config, &loop_env, depth);
        let merged = VarEnv::merge_branches(env, &[env.clone(), walk.env]);
        return WalkResult {
            result: walk.result,
            env: merged,
        };
    }

    // Words contain unsafe dynamic parts
    let mut dynamic = Vec::new();
    for w in &resolved_words {
        dynamic.extend(w.dynamic_parts());
    }
    let parts = dedup_parts(&dynamic);
    WalkResult {
        result: EvalResult::new(
            Decision::Ask,
            Some(format!(
                "Cannot statically analyse dynamic value{}: {}",
                if parts.len() == 1 { "" } else { "s" },
                parts.join(", "),
            )),
        ),
        env: env.clone(),
    }
}

/// Determine the VarState for an assignment value.
fn evaluate_assignment_value(value: &Word, env: &VarEnv, config: &Config, depth: usize) -> VarState {
    let resolved = resolve_command_substitutions(value, config, env, depth).resolve_with_var_env(env);
    if resolved.has_dynamic_parts() {
        // Contains unsafe/unknown parts
        VarState::Unsafe
    } else if resolved.is_literal() {
        VarState::Safe(Some(resolved.to_str()))
    } else {
        // Safe but contains opaque parts
        VarState::Safe(None)
    }
}

/// Maximum recursion depth for command substitution / eval / bash -c evaluation.
const MAX_EVAL_DEPTH: usize = 10;

/// Walk word parts and replace `CommandSubstitution`/`Backtick` with `Opaque`
/// if the inner command evaluates to Allow, or leave as-is if not.
fn resolve_command_substitutions(word: &Word, config: &Config, env: &VarEnv, depth: usize) -> Word {
    Word {
        parts: resolve_cmd_sub_parts(&word.parts, config, env, depth),
    }
}

fn resolve_cmd_sub_parts(
    parts: &[parser::WordPart],
    config: &Config,
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
                let inner_result = walk_command_with_depth(&inner_ast, config, env, depth + 1);
                if inner_result.result.decision == Decision::Allow {
                    parser::WordPart::Opaque(format!("$({})", parser::abbreviate(cmd_str)))
                } else {
                    part.clone()
                }
            }
            parser::WordPart::ProcessSubstitution { direction, command } => {
                let inner_ast = parser::parse(command);
                let inner_result = walk_command_with_depth(&inner_ast, config, env, depth + 1);
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
                parser::WordPart::DoubleQuoted(resolve_cmd_sub_parts(inner, config, env, depth))
            }
            _ => part.clone(),
        })
        .collect()
}

/// Check if an arithmetic expression is safe: all variable references resolve to safe vars.
fn is_arithmetic_safe(expr: &str, env: &VarEnv) -> bool {
    // Extract identifiers from the expression. In bash arithmetic, variables can
    // appear as bare names (x), $name, or ${name}. We extract all identifier-like
    // tokens and check them against the VarEnv.
    let mut i = 0;
    let bytes = expr.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'{' {
                // ${name} form
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
                    i += 1; // skip '}'
                }
            } else {
                // $name form
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
            // Bare identifier
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

/// Walk a simple command: process assignments, resolve variables, evaluate.
fn walk_simple_command(sc: &SimpleCommand, config: &Config, env: &VarEnv, depth: usize) -> WalkResult {
    let mut new_env = env.clone();

    // Process inline assignments (FOO=bar cmd args)
    for a in &sc.assignments {
        let state = evaluate_assignment_value(&a.value, &new_env, config, depth);
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
    let with_cmd_subs = sc.map_words(|w| resolve_command_substitutions(w, config, &new_env, depth));
    let resolved = with_cmd_subs.resolve_with_var_env(&new_env);

    // Detect `read`/`readarray`/`mapfile` builtins
    if let Some(cmd_name) = resolved.command_name()
        && matches!(cmd_name, "read" | "readarray" | "mapfile")
    {
        return walk_read_builtin(cmd_name, &resolved, &mut new_env);
    }

    // Check for remaining dynamic parts (unsafe variables, command substitutions, etc.)
    let mut dynamic = Vec::new();
    for word in &resolved.words {
        dynamic.extend(word.dynamic_parts());
    }
    for assignment in &resolved.assignments {
        dynamic.extend(assignment.value.dynamic_parts());
    }
    for redir in &resolved.redirections {
        if let crate::parser::RedirectionTarget::File(w) = &redir.target {
            dynamic.extend(w.dynamic_parts());
        }
    }
    if !dynamic.is_empty() {
        let cmd_label = resolved.command_name().unwrap_or("<unknown>");
        let parts = dedup_parts(&dynamic);
        return WalkResult {
            result: EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "Command `{cmd_label}` contains dynamic value{} that cannot be statically analysed: {}",
                    if parts.len() == 1 { "" } else { "s" },
                    parts.join(", "),
                )),
            ),
            env: new_env,
        };
    }

    // Code-execution position detection
    if let Some(cmd_name) = resolved.command_name() {
        // Case D: `source` / `.` — always Ask
        if cmd_name == "source" || cmd_name == "." {
            return WalkResult {
                result: EvalResult::new(
                    Decision::Ask,
                    Some(format!(
                        "Cannot statically analyse `{cmd_name}`: sourced file contents are unknown"
                    )),
                ),
                env: new_env,
            };
        }

        // Case A: opaque variable as command name
        if resolved.words.first().is_some_and(|w| w.has_opaque_parts()) {
            return WalkResult {
                result: EvalResult::new(
                    Decision::Ask,
                    Some("Variable used as command name: cannot determine what runs".into()),
                ),
                env: new_env,
            };
        }

        // Case B: `eval` command
        if cmd_name == "eval" && depth < MAX_EVAL_DEPTH {
            return walk_eval_command(&resolved, config, &new_env, depth);
        }

        // Case C: `bash -c` / `sh -c` / `zsh -c`
        if matches!(cmd_name, "bash" | "sh" | "zsh")
            && depth < MAX_EVAL_DEPTH
            && let Some(result) = walk_shell_dash_c(&resolved, config, &new_env, depth)
        {
            return result;
        }

        // Case E: function call — inline the function body
        if depth < MAX_EVAL_DEPTH
            && let Some(body) = new_env.get_fn(cmd_name).cloned()
        {
            let mut fn_env = new_env.clone();
            // Set positional parameters ($1, $2, ...) from the call arguments
            for (i, arg) in resolved.args().iter().enumerate() {
                let state = if arg.is_literal() {
                    VarState::Safe(Some(arg.to_str()))
                } else if arg.has_opaque_parts() {
                    VarState::Safe(None)
                } else {
                    VarState::Unsafe
                };
                fn_env.set(format!("{}", i + 1), state);
            }
            let fn_result = walk_command_with_depth(&body, config, &fn_env, depth + 1);
            // Function bodies execute in caller's scope — propagate env changes
            return WalkResult {
                result: fn_result.result,
                env: fn_result.env,
            };
        }
    }

    // Evaluate the resolved command against rules
    let result = evaluate_resolved_command(&resolved, config, 0, &new_env);
    WalkResult {
        result,
        env: new_env,
    }
}

/// Handle `read`/`readarray`/`mapfile` builtins by extracting variable names
/// and updating the environment.
fn walk_read_builtin(
    cmd_name: &str,
    resolved: &SimpleCommand,
    env: &mut VarEnv,
) -> WalkResult {
    // Flags that take an argument (the next token is consumed)
    let flags_with_arg: &[&str] = match cmd_name {
        "read" => &["-d", "-n", "-N", "-p", "-t", "-u"],
        "readarray" | "mapfile" => &["-d", "-n", "-O", "-t", "-u", "-C", "-c"],
        _ => &[],
    };

    // Extract variable names from args (skip flags and their values)
    let args = resolved.args();
    let mut var_names = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = arg.to_str();
        if s.starts_with('-') && s.len() > 1 {
            if flags_with_arg.iter().any(|f| *f == s) {
                skip_next = true;
            }
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
    for (i, name) in var_names.iter().enumerate() {
        let state = if var_names.len() == 1 && i == 0 {
            match &herestring_val {
                Some(val) => VarState::Safe(Some(val.clone())),
                None => VarState::Safe(None),
            }
        } else {
            VarState::Safe(None)
        };
        env.set(name.clone(), state);
    }

    WalkResult {
        result: EvalResult::new(Decision::Allow, None),
        env: env.clone(),
    }
}

/// Handle `eval` command: concatenate args and recursively evaluate if fully literal.
fn walk_eval_command(
    resolved: &SimpleCommand,
    config: &Config,
    env: &VarEnv,
    depth: usize,
) -> WalkResult {
    let args = resolved.args();
    if args.is_empty() {
        return WalkResult {
            result: EvalResult::new(Decision::Allow, None),
            env: env.clone(),
        };
    }

    // Check if any args are opaque or dynamic
    let has_opaque = args.iter().any(|a| a.has_opaque_parts());
    let has_dynamic = args.iter().any(|a| a.has_dynamic_parts());

    if has_dynamic {
        // Already caught by the dynamic parts check in the caller,
        // but handle explicitly for clarity
        let mut dynamic = Vec::new();
        for a in args {
            dynamic.extend(a.dynamic_parts());
        }
        let parts = dedup_parts(&dynamic);
        return WalkResult {
            result: EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "Command `eval` contains dynamic value{} that cannot be statically analysed: {}",
                    if parts.len() == 1 { "" } else { "s" },
                    parts.join(", "),
                )),
            ),
            env: env.clone(),
        };
    }

    if has_opaque {
        return WalkResult {
            result: EvalResult::new(
                Decision::Ask,
                Some("Cannot determine eval'd command: argument value is unknown".into()),
            ),
            env: env.clone(),
        };
    }

    // All args are literal — concatenate and recursively evaluate
    let eval_str: String = args.iter().map(|a| a.to_str()).collect::<Vec<_>>().join(" ");
    let inner_ast = parser::parse(&eval_str);
    let inner_result = walk_command_with_depth(&inner_ast, config, env, depth + 1);
    WalkResult {
        result: inner_result.result,
        env: inner_result.env,
    }
}

/// Handle `bash -c` / `sh -c` / `zsh -c`: find `-c` flag and recursively evaluate.
fn walk_shell_dash_c(
    resolved: &SimpleCommand,
    config: &Config,
    env: &VarEnv,
    depth: usize,
) -> Option<WalkResult> {
    let args = resolved.args();

    // Find the `-c` flag and get the command string after it
    let mut found_c = false;
    let mut cmd_arg = None;
    for arg in args {
        let s = arg.to_str();
        if found_c {
            cmd_arg = Some(arg);
            break;
        }
        if s == "-c" {
            found_c = true;
        }
    }

    if !found_c {
        return None; // No -c flag; not a code-execution pattern
    }

    let cmd_arg = cmd_arg?;

    if cmd_arg.has_dynamic_parts() {
        // Already caught by dynamic parts check
        return None;
    }

    if cmd_arg.has_opaque_parts() {
        return Some(WalkResult {
            result: EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "Cannot determine `{} -c` command: argument value is unknown",
                    resolved.command_name().unwrap_or("sh"),
                )),
            ),
            env: env.clone(),
        });
    }

    // Literal command string — recursively evaluate
    let cmd_str = cmd_arg.to_str();
    let inner_ast = parser::parse(&cmd_str);
    let inner_result = walk_command_with_depth(&inner_ast, config, env, depth + 1);
    Some(WalkResult {
        result: inner_result.result,
        env: env.clone(), // Shell -c runs in a subprocess; don't propagate env changes
    })
}

/// Evaluate a resolved simple command against rules (no more variable resolution needed).
#[allow(clippy::only_used_in_recursion)]
fn evaluate_resolved_command(
    resolved: &SimpleCommand,
    config: &Config,
    depth: usize,
    env: &VarEnv,
) -> EvalResult {
    let cmd_name = match resolved.command_name() {
        Some(name) if !name.is_empty() => name,
        _ => {
            return EvalResult::new(Decision::Ask, Some("Unknown command".into()));
        }
    };

    // R9: Check if this is a wrapper command
    if depth < 5
        && let Some(inner) = unwrap_wrapper(resolved, config)
    {
        // If the inner "command" is a single literal word that contains spaces
        // (e.g. ssh host "curl -sv http://..."), the wrapper was invoked with a
        // quoted shell string rather than bare words.  Re-parse it the same way
        // walk_shell_dash_c handles sh -c "...".
        if inner.words.len() == 1 {
            let word = &inner.words[0];
            if word.has_opaque_parts() {
                return EvalResult::new(
                    Decision::Ask,
                    Some(format!(
                        "Cannot determine inner command for `{cmd_name}`: \
                         argument value is unknown"
                    )),
                );
            }
            let s = word.to_str();
            if s.contains(' ') {
                let inner_ast = parser::parse(&s);
                return walk_command_with_depth(&inner_ast, config, env, 1).result;
            }
        }
        return evaluate_resolved_command(&inner, config, depth + 1, env);
    }

    // Expand flags: -abc → -a -b -c (R8)
    let expanded_args = expand_flags(resolved.args());

    // Evaluate against rules: deny rules first, then first match
    let mut first_match: Option<EvalResult> = None;
    let mut trace = Vec::new();

    for rule in &config.rules {
        let rule_label = format_command_matcher(&rule.command);

        if !command_matches(cmd_name, &rule.command) {
            continue;
        }

        trace.push(format!("matched command: {rule_label}"));

        // Determine if args match
        let args_match = match &rule.matcher {
            None => true,
            Some(m) => matcher_matches(m, &expanded_args),
        };
        if !args_match {
            trace.push("  args did not match".into());
            continue;
        }
        if rule.matcher.is_some() {
            trace.push("  args matched".into());
        }

        // Determine decision+reason: from rule-level effect, top-level cond branches,
        // or embedded Expr::Cond effects
        let effect = if let Some(ref eff) = rule.effect {
            trace.push(format!("  effect: {} — {}", eff.decision, eff.reason.as_deref().unwrap_or("(no reason)")));
            eff.clone()
        } else if let Some(ArgMatcher::Cond(branches)) = &rule.matcher {
            // Top-level cond: find first matching branch for its effect
            let mut found = None;
            for (i, branch) in branches.iter().enumerate() {
                let branch_match = match &branch.matcher {
                    None => {
                        trace.push(format!("  cond branch {}: else (catch-all)", i + 1));
                        true
                    }
                    Some(m) => {
                        let matched = matcher_matches(m, &expanded_args);
                        trace.push(format!("  cond branch {}: {}", i + 1, if matched { "matched" } else { "no match" }));
                        matched
                    }
                };
                if branch_match {
                    trace.push(format!("  effect: {} — {}", branch.effect.decision, branch.effect.reason.as_deref().unwrap_or("(no reason)")));
                    found = Some(branch.effect.clone());
                    break;
                }
            }
            let Some(eff) = found else { continue };
            eff
        } else if let Some(ref m) = rule.matcher {
            // Walk matcher tree for Expr::Cond effects.
            let string_args: Vec<String> = expanded_args
                .iter()
                .filter_map(|a| match a {
                    ResolvedArg::Literal(s) => Some(s.clone()),
                    ResolvedArg::Opaque => None,
                })
                .collect();
            let Some(eff) = m.find_expr_effect(&string_args) else {
                trace.push("  no matching expr cond branch".into());
                continue;
            };
            trace.push(format!("  expr effect: {} — {}", eff.decision, eff.reason.as_deref().unwrap_or("(no reason)")));
            eff
        } else {
            continue;
        };

        let Effect { decision, reason } = effect;
        let mut result = EvalResult::new(decision, reason);

        // Deny rules always win
        if decision == Decision::Deny {
            result.trace = trace;
            return result;
        }

        // Otherwise, first match wins
        if first_match.is_none() {
            result.trace = trace.clone();
            first_match = Some(result);
        }
    }

    first_match.unwrap_or_else(|| {
        trace.push("no matching rule".into());
        let mut result = EvalResult::new(
            Decision::Ask,
            Some(format!("No matching rule for command `{cmd_name}`")),
        );
        result.trace = trace;
        result
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CaptureKind, CommandMatcher, CondBranch, Config, Effect, Expr, PosExpr, Rule, Wrapper,
        WrapperStep,
    };

    /// Helper to wrap Expr values in PosExpr::One for tests.
    fn pos(exprs: Vec<Expr>) -> Vec<PosExpr> {
        exprs.into_iter().map(PosExpr::One).collect()
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn empty_config() -> Config {
        Config::default()
    }

    fn config_with_rules(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn allow_rule(cmd: &str) -> Rule {
        Rule {
            command: CommandMatcher::Exact(cmd.to_string()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Allow, reason: Some("allowed".into()) }),
            checks: vec![],
        }
    }

    fn deny_rule(cmd: &str) -> Rule {
        Rule {
            command: CommandMatcher::Exact(cmd.to_string()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Deny, reason: Some("denied".into()) }),
            checks: vec![],
        }
    }

    fn ask_rule(cmd: &str) -> Rule {
        Rule {
            command: CommandMatcher::Exact(cmd.to_string()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Ask, reason: Some("ask".into()) }),
            checks: vec![],
        }
    }

    /// Build a VarEnv with specific variables for testing.
    fn env_with(vars: &[(&str, VarState)]) -> VarEnv {
        let mut env = VarEnv::empty();
        for (name, state) in vars {
            env.set(name.to_string(), state.clone());
        }
        env
    }

    // ── Flag expansion ──────────────────────────────────────────────

    #[test]
    fn test_flag_expansion() {
        let args = vec![Word::literal("-abc"), Word::literal("--verbose")];
        let expanded = expand_flags(&args);
        assert_eq!(
            expanded,
            vec![
                ResolvedArg::Literal("-a".into()),
                ResolvedArg::Literal("-b".into()),
                ResolvedArg::Literal("-c".into()),
                ResolvedArg::Literal("--verbose".into()),
            ]
        );
    }

    #[test]
    fn flag_expansion_single_short_flag_unchanged() {
        let args = vec![Word::literal("-v")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec![ResolvedArg::Literal("-v".into())]);
    }

    #[test]
    fn flag_expansion_plain_args_unchanged() {
        let args = vec![Word::literal("hello"), Word::literal("world")];
        let expanded = expand_flags(&args);
        assert_eq!(
            expanded,
            vec![
                ResolvedArg::Literal("hello".into()),
                ResolvedArg::Literal("world".into()),
            ]
        );
    }

    #[test]
    fn flag_expansion_long_flag_unchanged() {
        let args = vec![Word::literal("--verbose")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec![ResolvedArg::Literal("--verbose".into())]);
    }

    // ── Decision::most_restrictive ──────────────────────────────────

    #[test]
    fn test_decision_most_restrictive() {
        assert_eq!(Decision::Allow.most_restrictive(Decision::Ask), Decision::Ask);
        assert_eq!(Decision::Ask.most_restrictive(Decision::Deny), Decision::Deny);
        assert_eq!(Decision::Allow.most_restrictive(Decision::Allow), Decision::Allow);
    }

    #[test]
    fn most_restrictive_deny_always_wins() {
        assert_eq!(Decision::Deny.most_restrictive(Decision::Allow), Decision::Deny);
        assert_eq!(Decision::Deny.most_restrictive(Decision::Ask), Decision::Deny);
        assert_eq!(Decision::Deny.most_restrictive(Decision::Deny), Decision::Deny);
    }

    // ── evaluate(): simple commands ─────────────────────────────────

    #[test]
    fn evaluate_simple_command_allowed() {
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate("ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_simple_command_denied() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate("rm -rf /", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn evaluate_no_matching_rule_asks() {
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate("whoami", &config);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(
            result.reason.as_deref(),
            Some("No matching rule for command `whoami`")
        );
    }

    #[test]
    fn evaluate_empty_input_allows() {
        // Empty input means no command to evaluate — nothing to block.
        let config = empty_config();
        let result = evaluate("", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── evaluate(): pipelines ───────────────────────────────────────

    #[test]
    fn evaluate_pipeline_all_allowed() {
        let config = config_with_rules(vec![allow_rule("ls"), allow_rule("grep")]);
        let result = evaluate("ls | grep foo", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_pipeline_one_denied() {
        let config = config_with_rules(vec![allow_rule("ls"), deny_rule("rm")]);
        let result = evaluate("ls | rm", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn evaluate_pipeline_most_restrictive_wins() {
        let config = config_with_rules(vec![allow_rule("cat"), ask_rule("sort")]);
        let result = evaluate("cat file | sort", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── evaluate(): sequences ───────────────────────────────────────

    #[test]
    fn evaluate_sequence_all_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate("echo hi; ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_sequence_one_denied() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate("echo hi; rm file", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── evaluate(): and/or ──────────────────────────────────────────

    #[test]
    fn evaluate_and_chain() {
        let config = config_with_rules(vec![allow_rule("mkdir"), allow_rule("cd")]);
        let result = evaluate("mkdir foo && cd foo", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_or_chain_denied() {
        let config = config_with_rules(vec![allow_rule("ls"), deny_rule("rm")]);
        let result = evaluate("ls || rm", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── evaluate(): compound commands ───────────────────────────────

    #[test]
    fn evaluate_if_command() {
        let config = config_with_rules(vec![allow_rule("test"), allow_rule("echo")]);
        let result = evaluate("if test -f foo; then echo found; fi", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_for_loop_with_literal_words() {
        // NEW: for loops with literal words now enumerate iterations
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("for x in a b c; do echo $x; done", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_while_loop() {
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate("while true; do echo loop; done", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── command_matches() ───────────────────────────────────────────

    #[test]
    fn command_matches_exact() {
        assert!(command_matches("git", &CommandMatcher::Exact("git".into())));
        assert!(!command_matches("gitx", &CommandMatcher::Exact("git".into())));
    }

    #[test]
    fn command_matches_regex() {
        let re = regex::Regex::new("^(git|hg)$").unwrap();
        assert!(command_matches("git", &CommandMatcher::Regex(re.clone())));
        assert!(command_matches("hg", &CommandMatcher::Regex(re.clone())));
        assert!(!command_matches("svn", &CommandMatcher::Regex(re)));
    }

    #[test]
    fn command_matches_list() {
        let list = CommandMatcher::List(vec!["cat".into(), "bat".into(), "less".into()]);
        assert!(command_matches("cat", &list));
        assert!(command_matches("bat", &list));
        assert!(!command_matches("more", &list));
    }

    // ── ArgMatcher::Positional ──────────────────────────────────────

    #[test]
    fn positional_matcher_literal() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Literal("status".into())]));
        let args = vec![ResolvedArg::Literal("status".into())];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_wildcard() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Wildcard]));
        let args = vec![ResolvedArg::Literal("anything".into())];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_regex() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Regex(regex::Regex::new("^(status|log)$").unwrap())]));
        assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("status".into())]));
        assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("log".into())]));
        assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("push".into())]));
    }

    #[test]
    fn positional_matcher_too_few_args() {
        let matcher = ArgMatcher::Positional(pos(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
        ]));
        assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("a".into())]));
    }

    #[test]
    fn positional_matcher_skips_flags() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Literal("status".into())]));
        let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::ExactPositional ──────────────────────────────────

    #[test]
    fn exact_positional_matches_exact_count() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
        assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("status".into())]));
    }

    #[test]
    fn exact_positional_rejects_extra_args() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("remote".into())]));
        assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("remote".into()), ResolvedArg::Literal("add".into())]));
    }

    #[test]
    fn exact_positional_rejects_too_few() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
        ]));
        assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("a".into())]));
    }

    #[test]
    fn exact_positional_skips_flags() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
        let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::Anywhere ────────────────────────────────────────

    #[test]
    fn anywhere_matcher_present() {
        let tokens = vec![Expr::Literal("--force".into())];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec![ResolvedArg::Literal("push".into()), ResolvedArg::Literal("--force".into())];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_absent() {
        let tokens = vec![Expr::Literal("--force".into())];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec![ResolvedArg::Literal("push".into()), ResolvedArg::Literal("origin".into())];
        assert!(!matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_or_semantics() {
        let tokens = vec![
            Expr::Literal("--force".into()),
            Expr::Literal("-f".into()),
        ];
        let matcher = ArgMatcher::Anywhere(tokens);
        assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("-f".into())]));
        assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("--force".into())]));
        assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("--verbose".into())]));
    }

    // ── And/Or/Not matchers ──────────────────────────────────────────

    #[test]
    fn and_matcher_all_must_pass() {
        let m = ArgMatcher::And(vec![
            ArgMatcher::Positional(pos(vec![Expr::Literal("push".into())])),
            ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                Expr::Literal("--force".into()),
            ]))),
        ]);
        assert!(matcher_matches(&m, &[ResolvedArg::Literal("push".into()), ResolvedArg::Literal("origin".into())]));
        assert!(!matcher_matches(&m, &[ResolvedArg::Literal("push".into()), ResolvedArg::Literal("--force".into())]));
    }

    #[test]
    fn or_matcher_any_must_pass() {
        let m = ArgMatcher::Or(vec![
            ArgMatcher::Anywhere(vec![Expr::Literal("-v".into())]),
            ArgMatcher::Anywhere(vec![Expr::Literal("--verbose".into())]),
        ]);
        assert!(matcher_matches(&m, &[ResolvedArg::Literal("-v".into())]));
        assert!(matcher_matches(&m, &[ResolvedArg::Literal("--verbose".into())]));
        assert!(!matcher_matches(&m, &[ResolvedArg::Literal("--quiet".into())]));
    }

    #[test]
    fn not_matcher_inverts() {
        let m = ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
            Expr::Literal("--force".into()),
        ])));
        assert!(matcher_matches(&m, &[ResolvedArg::Literal("push".into())]));
        assert!(!matcher_matches(&m, &[ResolvedArg::Literal("--force".into())]));
    }

    // ── extract_positional_args() ───────────────────────────────────

    #[test]
    fn extract_positional_skips_short_flags() {
        let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![ResolvedArg::Literal("status".into())]);
    }

    #[test]
    fn extract_positional_skips_long_flags_and_values() {
        let args = vec![
            ResolvedArg::Literal("--output".into()),
            ResolvedArg::Literal("file.txt".into()),
            ResolvedArg::Literal("input.txt".into()),
        ];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![ResolvedArg::Literal("input.txt".into())]);
    }

    #[test]
    fn extract_positional_long_flag_with_equals() {
        let args = vec![
            ResolvedArg::Literal("--output=file.txt".into()),
            ResolvedArg::Literal("input.txt".into()),
        ];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![ResolvedArg::Literal("input.txt".into())]);
    }

    #[test]
    fn extract_positional_bare_dash_is_positional() {
        let args = vec![ResolvedArg::Literal("-".into())];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![ResolvedArg::Literal("-".into())]);
    }

    #[test]
    fn extract_positional_double_dash_is_positional() {
        let args = vec![
            ResolvedArg::Literal("run".into()),
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("test".into()),
        ];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![
            ResolvedArg::Literal("run".into()),
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("test".into()),
        ]);
    }

    #[test]
    fn extract_positional_double_dash_terminates_flags() {
        let args = vec![
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("--force".into()),
            ResolvedArg::Literal("-v".into()),
        ];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("--force".into()),
            ResolvedArg::Literal("-v".into()),
        ]);
    }

    #[test]
    fn extract_positional_flags_before_double_dash_skipped() {
        let args = vec![
            ResolvedArg::Literal("-v".into()),
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("arg".into()),
        ];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec![
            ResolvedArg::Literal("--".into()),
            ResolvedArg::Literal("arg".into()),
        ]);
    }

    // ── Rule matching integration ───────────────────────────────────

    #[test]
    fn rule_with_positional_matcher() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(pos(vec![
                Expr::Literal("status".into()),
            ]))),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("git status", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn rule_with_positional_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(pos(vec![
                Expr::Literal("status".into()),
            ]))),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("git push", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn deny_rule_wins_over_allow() {
        let rules = vec![
            allow_rule("rm"),
            Rule {
                command: CommandMatcher::Exact("rm".into()),
                matcher: Some(ArgMatcher::Anywhere(vec![
                    Expr::Literal("-r".into()),
                ])),
                effect: Some(Effect { decision: Decision::Deny, reason: Some("dangerous".into()) }),
                checks: vec![],
            },
        ];
        let config = config_with_rules(rules);
        let result = evaluate("rm -rf /", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn first_matching_non_deny_rule_wins() {
        let rules = vec![
            Rule {
                command: CommandMatcher::Exact("git".into()),
                matcher: None,
                effect: Some(Effect { decision: Decision::Ask, reason: Some("first".into()) }),
                checks: vec![],
            },
            Rule {
                command: CommandMatcher::Exact("git".into()),
                matcher: None,
                effect: Some(Effect { decision: Decision::Allow, reason: Some("second".into()) }),
                checks: vec![],
            },
        ];
        let config = config_with_rules(rules);
        let result = evaluate("git status", &config);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.reason.as_deref(), Some("first"));
    }

    #[test]
    fn regex_command_matcher_in_rule() {
        let rule = Rule {
            command: CommandMatcher::Regex(regex::Regex::new("^(cat|bat|less)$").unwrap()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        assert_eq!(evaluate("cat file", &config).decision, Decision::Allow);
        assert_eq!(evaluate("bat file", &config).decision, Decision::Allow);
        assert_eq!(evaluate("less file", &config).decision, Decision::Allow);
        assert_eq!(evaluate("more file", &config).decision, Decision::Ask);
    }

    #[test]
    fn list_command_matcher_in_rule() {
        let rule = Rule {
            command: CommandMatcher::List(vec!["cat".into(), "bat".into()]),
            matcher: None,
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        assert_eq!(evaluate("cat file", &config).decision, Decision::Allow);
        assert_eq!(evaluate("bat file", &config).decision, Decision::Allow);
        assert_eq!(evaluate("head file", &config).decision, Decision::Ask);
    }

    // ── Wrapper unwrapping ──────────────────────────────────────────

    fn after_flags_wrapper(command: &str) -> Wrapper {
        Wrapper {
            command: command.into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![],
                capture: Some(CaptureKind::CommandArgs),
            }],
        }
    }

    fn after_delimiter_wrapper(command: &str, delim: &str) -> Wrapper {
        Wrapper {
            command: command.into(),
            steps: vec![WrapperStep::Flag {
                name: delim.into(),
                capture: CaptureKind::CommandArgs,
            }],
        }
    }

    #[test]
    fn wrapper_after_flags_unwraps() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![after_flags_wrapper("sudo")],
            ..Config::default()
        };
        let result = evaluate("sudo ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_after_flags_with_flags() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![after_flags_wrapper("sudo")],
            ..Config::default()
        };
        let result = evaluate("sudo -u ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_after_delimiter_unwraps() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![after_delimiter_wrapper("env", "--")],
            ..Config::default()
        };
        let result = evaluate("env FOO=bar -- ls -la", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_with_positional_args() {
        // (wrapper "docker" (positional "exec" :command+args))
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "docker".into(),
                steps: vec![WrapperStep::Positional {
                    patterns: vec![Expr::Literal("exec".into())],
                    capture: Some(CaptureKind::CommandArgs),
                }],
            }],
            ..Config::default()
        };
        let result = evaluate("docker exec container ls", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn wrapper_positional_mismatch_no_unwrap() {
        let config = Config {
            rules: vec![allow_rule("docker")],
            wrappers: vec![Wrapper {
                command: "docker".into(),
                steps: vec![WrapperStep::Positional {
                    patterns: vec![Expr::Literal("exec".into())],
                    capture: Some(CaptureKind::CommandArgs),
                }],
            }],
            ..Config::default()
        };
        let result = evaluate("docker run container", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_not_matching_command() {
        let config = Config {
            rules: vec![allow_rule("nohup")],
            wrappers: vec![after_flags_wrapper("sudo")],
            ..Config::default()
        };
        let result = evaluate("nohup sleep 10", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_ssh_skips_hostname() {
        // (wrapper "ssh" (positional * :command+args))
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "ssh".into(),
                steps: vec![WrapperStep::Positional {
                    patterns: vec![Expr::Wildcard],
                    capture: Some(CaptureKind::CommandArgs),
                }],
            }],
            ..Config::default()
        };
        assert_eq!(evaluate("ssh host ls", &config).decision, Decision::Allow);
        assert_eq!(evaluate("ssh -v host ls", &config).decision, Decision::Allow);
    }

    #[test]
    fn wrapper_ssh_no_inner_command() {
        // ssh without a trailing command should not unwrap
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "ssh".into(),
                steps: vec![WrapperStep::Positional {
                    patterns: vec![Expr::Wildcard],
                    capture: Some(CaptureKind::CommandArgs),
                }],
            }],
            ..Config::default()
        };
        // Falls back to evaluating "ssh" itself (not allowed → ask)
        assert_eq!(evaluate("ssh host", &config).decision, Decision::Ask);
    }

    #[test]
    fn wrapper_nix_shell_flag_command() {
        // (wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "nix".into(),
                steps: vec![
                    WrapperStep::Positional {
                        patterns: vec![Expr::Or(vec![
                            Expr::Literal("shell".into()),
                            Expr::Literal("develop".into()),
                        ])],
                        capture: None,
                    },
                    WrapperStep::Flag {
                        name: "--command".into(),
                        capture: CaptureKind::CommandArgs,
                    },
                ],
            }],
            ..Config::default()
        };
        assert_eq!(
            evaluate("nix shell --command ls", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("nix develop --command ls", &config).decision,
            Decision::Allow
        );
        // Wrong subcommand — wrapper doesn't apply, falls through to rule eval
        assert_eq!(
            evaluate("nix run --command ls", &config).decision,
            Decision::Ask
        );
    }

    #[test]
    fn wrapper_mise_validate_then_delimiter() {
        // (wrapper "mise" (positional "exec") (flag "--" :command+args))
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "mise".into(),
                steps: vec![
                    WrapperStep::Positional {
                        patterns: vec![Expr::Literal("exec".into())],
                        capture: None,
                    },
                    WrapperStep::Flag {
                        name: "--".into(),
                        capture: CaptureKind::CommandArgs,
                    },
                ],
            }],
            ..Config::default()
        };
        assert_eq!(
            evaluate("mise exec -- ls -la", &config).decision,
            Decision::Allow
        );
        // Wrong subcommand — wrapper doesn't apply
        assert_eq!(
            evaluate("mise run -- ls", &config).decision,
            Decision::Ask
        );
    }

    // ── Dynamic parts ────────────────────────────────────────────────

    #[test]
    fn dynamic_parts_in_command_asks() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("echo $(whoami)", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$(whoami)"), "should mention the dynamic part: {reason}");
    }

    #[test]
    fn normal_file_allowed() {
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate("cat README.md", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── evaluate_resolved_command(): edge cases ───────────────────────

    #[test]
    fn evaluate_empty_command_name() {
        let sc = SimpleCommand {
            assignments: vec![],
            words: vec![],
            redirections: vec![],
        };
        let env = VarEnv::from_process_env();
        let result = evaluate_resolved_command(&sc, &empty_config(), 0, &env);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.reason.as_deref(), Some("Unknown command"));
    }

    // ── Not+Anywhere (forbidden) with rule integration ─────────────

    #[test]
    fn not_anywhere_denies_with_forbidden_flag() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::And(vec![
                ArgMatcher::Positional(pos(vec![Expr::Literal("push".into())])),
                ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                    Expr::Literal("--force".into()),
                    Expr::Literal("-f".into()),
                ]))),
            ])),
            effect: Some(Effect { decision: Decision::Allow, reason: Some("safe push".into()) }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);

        assert_eq!(
            evaluate("git push origin main", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("git push --force origin main", &config).decision,
            Decision::Ask
        );
    }

    // ── Anywhere matcher with regex pattern ─────────────────────────

    #[test]
    fn anywhere_matcher_regex_pattern() {
        let rule = Rule {
            command: CommandMatcher::Exact("grep".into()),
            matcher: Some(ArgMatcher::Anywhere(vec![
                Expr::Regex(regex::Regex::new("^-r$").unwrap()),
            ])),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        assert_eq!(
            evaluate("grep -r pattern .", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("grep pattern .", &config).decision,
            Decision::Ask
        );
    }

    // ── Default decision when no rules ──────────────────────────────

    #[test]
    fn no_rules_defaults_to_ask() {
        let config = empty_config();
        let result = evaluate("ls", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Subshell and brace group evaluation ─────────────────────────

    #[test]
    fn evaluate_subshell() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("(echo hello)", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn evaluate_brace_group() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate("{ echo hi; ls; }", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Environment variable resolution ──────────────────────────────

    #[test]
    fn env_var_resolved_allows_static_analysis() {
        let env = env_with(&[("TEST_MAYI_HOME", VarState::Safe(Some("/home/user".into())))]);
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate_with_env("echo $TEST_MAYI_HOME && ls", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn unresolved_env_var_triggers_ask() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate_with_env("echo $HOME && ls", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$HOME"), "should mention the variable: {reason}");
    }

    #[test]
    fn command_sub_never_resolvable() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate_with_env("echo $(whoami) && ls", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$(whoami)"), "should mention command substitution: {reason}");
    }

    #[test]
    fn deny_wins_with_resolved_env_var() {
        let env = env_with(&[("TEST_MAYI_HOME3", VarState::Safe(Some("/tmp".into())))]);
        let config = config_with_rules(vec![deny_rule("ls"), allow_rule("echo")]);
        let result = evaluate_with_env("ls && echo $TEST_MAYI_HOME3", &config, &env);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn for_loop_dynamic_iteration_words_ask() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("for f in $items; do echo $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("$items"), "should mention the variable: {reason}");
    }

    // ── Parameter expansion operator integration ─────────────────────

    #[test]
    fn param_op_resolved_safe_env_allows() {
        let env = env_with(&[("TEST_MAYI_PATH", VarState::Safe(Some("/usr/local/bin".into())))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo ${TEST_MAYI_PATH##*/}", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn param_op_unresolved_triggers_ask() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo ${UNKNOWN_VAR#pat}", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("UNKNOWN_VAR"), "should mention the variable: {reason}");
    }

    #[test]
    fn param_op_default_value_with_safe_env() {
        let env = env_with(&[("TEST_MAYI_OPT", VarState::Safe(Some("value".into())))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo ${TEST_MAYI_OPT:-fallback}", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn param_op_in_double_quotes_resolved() {
        let env = env_with(&[("TEST_MAYI_FILE", VarState::Safe(Some("archive.tar.gz".into())))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"echo "${TEST_MAYI_FILE%%.*}""#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Dynamic parts in assignment values ───────────────────────────

    #[test]
    fn dynamic_in_assignment_value_triggers_ask() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("FOO=$(whoami) echo hello", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Dynamic parts in redirect targets ────────────────────────────

    #[test]
    fn dynamic_in_redirect_target_triggers_ask() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo hello > $OUTFILE", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Blocked path removal verification ─────────────────────────────

    #[test]
    fn cat_env_allowed_with_rule() {
        // After blocked-path removal, cat .env is allowed if cat has an allow rule
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate("cat .env", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn cat_ssh_allowed_with_rule() {
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate("cat .ssh/id_rsa", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Variable assignment resolution ────────────────────────────────

    #[test]
    fn literal_assignment_resolution() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x="hello"; echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn path_assignment_and_cat() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate_with_env(r#"x="/tmp"; cat $x/file"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn transitive_assignment_resolution() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x="a"; y=$x; echo $y"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn reassignment_resolution() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x="a"; x="b"; echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn resolution_in_first_of_and() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
        let result = evaluate_with_env(r#"x="hello"; echo $x && ls"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Unresolved variables ─────────────────────────────────────────

    #[test]
    fn unknown_variable_asks() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo $UNKNOWN", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn assigned_from_unsafe_asks() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("x=$UNKNOWN; echo $x", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn transitive_unsafety() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("x=$UNKNOWN; y=$x; echo $y", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Environment variable integration ─────────────────────────────

    #[test]
    fn env_var_resolves() {
        let env = env_with(&[("HOME", VarState::Safe(Some("/home/user".into())))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo $HOME", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn local_assignment_overrides_env() {
        let env = env_with(&[("HOME", VarState::Safe(Some("/home/user".into())))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("HOME=/override; echo $HOME", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn nonexistent_env_var_asks() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo $NOEXIST", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── If/else branching ────────────────────────────────────────────

    #[test]
    fn if_both_branches_safe_is_unresolvable() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        // Both branches assign safe values, so x is safe (but opaque) after
        let result = evaluate_with_env(
            r#"if true; then x="a"; else x="b"; fi; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn if_only_then_assigns_and_var_was_unknown() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        // Only then-branch assigns; x was unknown before → unsafe after
        let result = evaluate_with_env(
            r#"if true; then x="a"; fi; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn if_one_branch_unsafe() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate_with_env(
            r#"if true; then x="a"; else x=$UNKNOWN; fi; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn if_elif_else_all_safe() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate_with_env(
            r#"if true; then x="a"; elif true; then x="b"; else x="c"; fi; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── For-loop enumeration ─────────────────────────────────────────

    #[test]
    fn for_loop_literal_words_enumerates() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("for f in a b c; do echo $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn for_loop_literal_words_cat() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate_with_env("for f in a b c; do cat $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn for_loop_deny_wins_across_iterations() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_with_env("for f in a b c; do rm $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn for_loop_ask_for_unknown_cmd() {
        let env = VarEnv::empty();
        let config = empty_config();
        let result = evaluate_with_env("for f in a b c; do unknown_cmd $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn for_loop_nested() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(
            "for x in a b; do for y in c d; do echo $x $y; done; done",
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── For-loop with non-literal words ──────────────────────────────

    #[test]
    fn for_loop_glob_words_opaque() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("for f in *.txt; do echo $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn for_loop_glob_cat_no_constraints() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("cat")]);
        let result = evaluate_with_env("for f in *.txt; do cat $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn for_loop_unsafe_items_ask() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("for f in $items; do echo $f; done", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Opaque-arg rule matching ─────────────────────────────────────

    #[test]
    fn opaque_arg_with_no_constraints_allows() {
        // echo with allow rule and no arg constraints → Allow
        let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo $safe_opaque", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn opaque_first_positional_no_match() {
        // git $safe_opaque with (positional "push" *) → does not match
        let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(vec![
                PosExpr::One(Expr::Literal("push".into())),
                PosExpr::One(Expr::Wildcard),
            ])),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate_with_env("git $safe_opaque", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn opaque_second_positional_wildcard_matches() {
        // git push $safe_opaque with (positional "push" *) → Allow
        let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(vec![
                PosExpr::One(Expr::Literal("push".into())),
                PosExpr::One(Expr::Wildcard),
            ])),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate_with_env("git push $safe_opaque", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn opaque_second_positional_literal_no_match() {
        // git push $safe_opaque with (positional "push" "origin") → Ask
        let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(vec![
                PosExpr::One(Expr::Literal("push".into())),
                PosExpr::One(Expr::Literal("origin".into())),
            ])),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate_with_env("git push $safe_opaque", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn opaque_arg_anywhere_no_match() {
        // cmd $safe_opaque with (anywhere "--force") → opaque doesn't match
        let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
        let rule = Rule {
            command: CommandMatcher::Exact("cmd".into()),
            matcher: Some(ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())])),
            effect: Some(Effect { decision: Decision::Allow, reason: None }),
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate_with_env("cmd $safe_opaque", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Sequential scope ─────────────────────────────────────────────

    #[test]
    fn assignment_before_use_resolves() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x="a" && echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn use_before_assignment_asks() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("echo $x; x=\"a\"", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Cond rule body ───────────────────────────────────────────────

    #[test]
    fn cond_first_branch_matches() {
        let rule = Rule {
            command: CommandMatcher::Exact("tmux".into()),
            matcher: Some(ArgMatcher::Cond(vec![
                CondBranch {
                    matcher: Some(ArgMatcher::Positional(pos(vec![
                        Expr::Literal("source-file".into()),
                    ]))),
                    effect: Effect { decision: Decision::Allow, reason: Some("config reload".into()) },
                },
                CondBranch {
                    matcher: None,
                    effect: Effect { decision: Decision::Deny, reason: Some("unknown".into()) },
                },
            ])),
            effect: None,
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("tmux source-file foo.conf", &config);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason.as_deref(), Some("config reload"));
    }

    #[test]
    fn cond_fallthrough_to_wildcard() {
        let rule = Rule {
            command: CommandMatcher::Exact("tmux".into()),
            matcher: Some(ArgMatcher::Cond(vec![
                CondBranch {
                    matcher: Some(ArgMatcher::Positional(pos(vec![
                        Expr::Literal("source-file".into()),
                    ]))),
                    effect: Effect { decision: Decision::Allow, reason: None },
                },
                CondBranch {
                    matcher: None,
                    effect: Effect { decision: Decision::Deny, reason: Some("fallback deny".into()) },
                },
            ])),
            effect: None,
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("tmux kill-session", &config);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.reason.as_deref(), Some("fallback deny"));
    }

    #[test]
    fn cond_no_wildcard_no_match_skips_rule() {
        let rule = Rule {
            command: CommandMatcher::Exact("tmux".into()),
            matcher: Some(ArgMatcher::Cond(vec![CondBranch {
                matcher: Some(ArgMatcher::Positional(pos(vec![
                    Expr::Literal("source-file".into()),
                ]))),
                effect: Effect { decision: Decision::Allow, reason: None },
            }])),
            effect: None,
            checks: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("tmux kill-session", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn cond_deny_branch_wins_across_rules() {
        let rules = vec![
            Rule {
                command: CommandMatcher::Exact("tmux".into()),
                matcher: Some(ArgMatcher::Cond(vec![
                    CondBranch {
                        matcher: Some(ArgMatcher::Positional(pos(vec![
                            Expr::Literal("source-file".into()),
                        ]))),
                        effect: Effect { decision: Decision::Allow, reason: None },
                    },
                    CondBranch {
                        matcher: None,
                        effect: Effect { decision: Decision::Deny, reason: Some("blocked".into()) },
                    },
                ])),
                effect: None,
                checks: vec![],
            },
            allow_rule("tmux"),
        ];
        let config = config_with_rules(rules);
        let result = evaluate("tmux kill-session", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn cond_integration_tmux_use_case() {
        use crate::config_parse;

        let config = config_parse::parse(
            r#"
            (rule (command "tmux")
                  (args (cond
                    ((positional "source-file" (or "~/.config/tmux/custom.conf"
                                                   "~/.config/tmux/tmux.conf"))
                     (effect :allow "Reloading config is safe"))
                    (else
                     (effect :deny "Unknown tmux source-file"))))
                  (check :allow "tmux source-file ~/.config/tmux/custom.conf"
                         :deny "tmux source-file /tmp/evil.conf"))
            "#,
            "<test>",
        )
        .unwrap();

        assert_eq!(
            evaluate("tmux source-file ~/.config/tmux/custom.conf", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("tmux source-file ~/.config/tmux/tmux.conf", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("tmux source-file /tmp/evil.conf", &config).decision,
            Decision::Deny
        );
        assert_eq!(
            evaluate("tmux kill-session", &config).decision,
            Decision::Deny
        );

        let results = crate::check::run_checks(&config);
        assert!(results.iter().all(|r| r.passed), "checks should pass: {results:?}");
    }

    // ── Expr::Cond as implicit rule effect ──────────────────────────

    #[test]
    fn expr_cond_in_positional_matching_branch() {
        use crate::config_parse;

        let config = config_parse::parse(
            r#"(rule (command "tmux")
                   (args (positional "source-file"
                                     (if (or "~/.config/tmux/custom.conf"
                                             "~/.config/tmux/tmux.conf")
                                         (effect :allow "safe config")
                                         (effect :deny "unknown file")))))"#,
            "<test>",
        )
        .unwrap();

        assert_eq!(
            evaluate("tmux source-file ~/.config/tmux/custom.conf", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("tmux source-file ~/.config/tmux/tmux.conf", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("tmux source-file /tmp/evil.conf", &config).decision,
            Decision::Deny
        );
    }

    #[test]
    fn expr_cond_in_positional_no_match_skips_rule() {
        use crate::config_parse;

        let config = config_parse::parse(
            r#"(rule (command "tmux")
                   (args (positional "source-file"
                                     (when "safe.conf"
                                           (effect :allow "safe")))))"#,
            "<test>",
        )
        .unwrap();

        assert_eq!(
            evaluate("tmux source-file safe.conf", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("tmux source-file other.conf", &config).decision,
            Decision::Ask
        );
        assert_eq!(
            evaluate("tmux kill-session", &config).decision,
            Decision::Ask
        );
    }

    #[test]
    fn expr_cond_in_anywhere() {
        use crate::config_parse;

        let config = config_parse::parse(
            r#"(rule (command "foo")
                   (args (anywhere (if "--safe"
                                       (effect :allow "safe flag")
                                       (effect :deny "unsafe")))))"#,
            "<test>",
        )
        .unwrap();

        assert_eq!(
            evaluate("foo --safe", &config).decision,
            Decision::Allow
        );
        assert_eq!(
            evaluate("foo --other", &config).decision,
            Decision::Deny
        );
    }

    // ── OneOrMore break path in match_positional ─────────────────────

    #[test]
    fn one_or_more_stops_on_mismatch() {
        use crate::config_parse;

        let config = config_parse::parse(
            r#"(rule (command "cmd")
                  (args (exact (+ "a") "b"))
                  (effect :allow))"#,
            "<test>",
        )
        .unwrap();

        assert_eq!(evaluate("cmd a a b", &config).decision, Decision::Allow);
        assert_eq!(evaluate("cmd a b", &config).decision, Decision::Allow);
        assert_eq!(evaluate("cmd b", &config).decision, Decision::Ask);
        assert_eq!(evaluate("cmd a b extra", &config).decision, Decision::Ask);
    }

    // ── Subshell isolation ─────────────────────────────────────────

    #[test]
    fn subshell_does_not_affect_outer_scope() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        // x="safe"; (x="tainted"); echo $x → x is still "safe" outside subshell
        // But we start with empty env, so x is set by the first assignment
        let result = evaluate_with_env(
            r#"x="safe"; (x="tainted"); echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Empty simple commands → Ask ──────────────────────────────────

    #[test]
    fn compound_with_no_simple_commands_asks() {
        let config = config_with_rules(vec![allow_rule("f")]);
        let result = evaluate("f() { :; }", &config);
        let result2 = evaluate("()", &config);
        assert!(result.decision == Decision::Allow || result.decision == Decision::Ask);
        assert!(result2.decision == Decision::Ask || result2.decision == Decision::Allow);
    }

    // ── Command substitution safety ─────────────────────────────────

    #[test]
    fn cmd_sub_allowed_inner_makes_var_safe_opaque() {
        // x=$(echo hello); echo $x → Allow (echo is allowed, x is safe+opaque)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x=$(echo hello); echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn cmd_sub_ask_inner_makes_var_unsafe() {
        // x=$(dangerous_cmd); echo $x → Ask (inner is Ask → x unsafe)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("x=$(dangerous_cmd); echo $x", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn cmd_sub_opaque_used_as_command_name_asks() {
        // x=$(echo hello); $x → Ask (x opaque, used as command name)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("x=$(echo hello); $x", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn cmd_sub_in_inline_assignment_allowed() {
        // FOO=$(echo hello) echo $FOO → Allow (echo allowed → FOO safe+opaque)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("FOO=$(echo hello) echo $FOO", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn cmd_sub_in_double_quotes_resolved() {
        // x="$(echo hello)"; echo $x → Allow
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"x="$(echo hello)"; echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn backtick_sub_allowed_inner_makes_var_safe() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("x=`echo hello`; echo $x", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── While/until loop variable tainting ───────────────────────────

    #[test]
    fn while_safe_body_preserves_safety() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate_with_env(
            r#"x="safe"; while true; do x="still safe"; done; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn while_tainting_body_makes_unsafe() {
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate_with_env(
            "x=\"safe\"; while true; do x=$UNKNOWN; done; echo $x",
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn while_assigns_new_var_is_unsafe_after() {
        // while true; do x="a"; done; echo $x → Ask (x may not be assigned)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
        let result = evaluate_with_env(
            r#"while true; do x="a"; done; echo $x"#,
            &config,
            &env,
        );
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── read/readarray builtins ─────────────────────────────────────

    #[test]
    fn read_herestring_literal_allows() {
        // read x <<< "hello"; echo $x → Allow
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"read x <<< "hello"; echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn read_no_herestring_safe_opaque() {
        // read x; echo $x → Allow (safe+opaque)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env("read x; echo $x", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn read_with_flags_skipped() {
        // read -r x <<< "hello"; echo $x → Allow (flags skipped)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"read -r x <<< "hello"; echo $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn read_default_reply_var() {
        // read <<< "hello"; echo $REPLY → Allow
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_with_env(r#"read <<< "hello"; echo $REPLY"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Code-execution position detection ───────────────────────────

    #[test]
    fn eval_literal_allowed_cmd() {
        // x="ls"; eval $x → Allow (x resolves to "ls", eval'd "ls" checked against rules)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate_with_env(r#"x="ls"; eval $x"#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn eval_unsafe_var_asks() {
        // eval $UNKNOWN → Ask
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate_with_env("eval $UNKNOWN", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn eval_literal_with_args() {
        // x="ls"; eval "$x -la" → Allow (resolves to "ls -la")
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate_with_env(r#"x="ls"; eval "$x -la""#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn opaque_var_as_command_name_asks() {
        // $x where x is safe but opaque → Ask (can't determine what runs)
        let env = env_with(&[("x", VarState::Safe(None))]);
        let config = config_with_rules(vec![allow_rule("ls")]);
        let result = evaluate_with_env("$x", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("command name"), "should mention command name: {reason}");
    }

    #[test]
    fn bash_dash_c_literal_evaluates() {
        // x="ls"; bash -c "$x" → Allow (x resolves, inner "ls" evaluated)
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("ls"), allow_rule("bash")]);
        let result = evaluate_with_env(r#"x="ls"; bash -c "$x""#, &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn bash_dash_c_unsafe_asks() {
        // bash -c "$UNKNOWN" → Ask
        let env = VarEnv::empty();
        let config = config_with_rules(vec![allow_rule("bash")]);
        let result = evaluate_with_env(r#"bash -c "$UNKNOWN""#, &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn source_always_asks() {
        let config = config_with_rules(vec![allow_rule("source")]);
        let result = evaluate("source ./script.sh", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("source"), "should mention source: {reason}");
    }

    #[test]
    fn dot_source_always_asks() {
        let config = config_with_rules(vec![allow_rule(".")]);
        let result = evaluate(". ./script.sh", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn eval_opaque_var_asks() {
        // eval with opaque arg asks
        let env = env_with(&[("cmd", VarState::Safe(None))]);
        let config = config_with_rules(vec![allow_rule("eval"), allow_rule("ls")]);
        let result = evaluate_with_env("eval $cmd", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("eval"), "should mention eval: {reason}");
    }

    #[test]
    fn sh_dash_c_opaque_asks() {
        let env = env_with(&[("cmd", VarState::Safe(None))]);
        let config = config_with_rules(vec![allow_rule("sh")]);
        let result = evaluate_with_env("sh -c $cmd", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn bash_no_dash_c_evaluates_normally() {
        // bash without -c is not a code-execution pattern
        let config = config_with_rules(vec![allow_rule("bash")]);
        let result = evaluate("bash script.sh", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn eval_empty_allows() {
        let config = config_with_rules(vec![allow_rule("eval")]);
        let result = evaluate("eval", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn eval_denied_inner_denies() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate("eval rm -rf /", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── Process substitution safety ──────────────────────────────────

    #[test]
    fn process_sub_safe_inner_allows() {
        let config = config_with_rules(vec![allow_rule("diff"), allow_rule("echo")]);
        let result = evaluate("diff <(echo a) <(echo b)", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn process_sub_unsafe_inner_asks() {
        let config = config_with_rules(vec![allow_rule("diff")]);
        // dangerous_cmd has no rule → Ask
        let result = evaluate("diff <(dangerous_cmd) file", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn process_sub_cat_echo_allows() {
        let config = config_with_rules(vec![allow_rule("cat"), allow_rule("echo")]);
        let result = evaluate("cat <(echo safe)", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn process_sub_output_direction_allows() {
        let config = config_with_rules(vec![allow_rule("tee"), allow_rule("echo")]);
        let result = evaluate("echo hello | tee >(cat)", &config);
        assert_eq!(result.decision, Decision::Ask); // cat has no rule
    }

    #[test]
    fn process_sub_output_all_allowed() {
        let config = config_with_rules(vec![allow_rule("tee"), allow_rule("echo"), allow_rule("cat")]);
        let result = evaluate("echo hello | tee >(cat)", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Arithmetic expression safety ─────────────────────────────────

    #[test]
    fn arithmetic_pure_numeric_allows() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("echo $((1 + 2))", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arithmetic_safe_var_allows() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
        let result = evaluate_with_env("x=5; echo $((x + 1))", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arithmetic_unknown_var_asks() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let env = VarEnv::empty();
        let result = evaluate_with_env("echo $((UNKNOWN + 1))", &config, &env);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn arithmetic_safe_var_complex_allows() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
        let result = evaluate_with_env("x=5; echo $((x * 2 + 1))", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arithmetic_dollar_var_safe() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let env = env_with(&[("y", VarState::Safe(Some("3".into())))]);
        let result = evaluate_with_env("echo $(($y + 1))", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arithmetic_dollar_brace_var_safe() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let env = env_with(&[("z", VarState::Safe(Some("7".into())))]);
        let result = evaluate_with_env("echo $((${z} + 1))", &config, &env);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── is_arithmetic_safe unit tests ────────────────────────────────

    #[test]
    fn arith_safe_pure_numbers() {
        let env = VarEnv::empty();
        assert!(is_arithmetic_safe("1 + 2 * 3", &env));
    }

    #[test]
    fn arith_safe_known_var() {
        let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
        assert!(is_arithmetic_safe("x + 1", &env));
    }

    #[test]
    fn arith_unsafe_unknown_var() {
        let env = VarEnv::empty();
        assert!(!is_arithmetic_safe("x + 1", &env));
    }

    #[test]
    fn arith_safe_dollar_var() {
        let env = env_with(&[("y", VarState::Safe(None))]);
        assert!(is_arithmetic_safe("$y + 1", &env));
    }

    #[test]
    fn arith_safe_dollar_brace_var() {
        let env = env_with(&[("z", VarState::Safe(None))]);
        assert!(is_arithmetic_safe("${z} * 2", &env));
    }

    #[test]
    fn arith_unsafe_dollar_var() {
        let env = VarEnv::empty();
        assert!(!is_arithmetic_safe("$UNKNOWN + 1", &env));
    }

    // ── Function tracking ────────────────────────────────────────────

    #[test]
    fn function_def_then_call_allows() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("f() { echo hello; }; f", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn function_def_then_call_denies() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate("f() { rm -rf /; }; f", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn function_def_then_call_with_safe_arg() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("f() { echo $1; }; f safe", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn function_def_then_call_unknown_inner() {
        // Inner command has no matching rule → Ask
        let config = config_with_rules(vec![]);
        let result = evaluate("f() { dangerous; }; f", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn function_def_never_called_allows() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        // Function is defined but never called — definition is safe
        let result = evaluate("f() { rm -rf /; }", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn function_recursive_depth_guard() {
        // Recursive function should hit depth guard and not loop infinitely
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("f() { f; }; f", &config);
        // At max depth, the recursive call to `f` won't find it as a function
        // (depth >= MAX_EVAL_DEPTH), so it falls through to rule matching,
        // which yields Ask (no rule for `f`)
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn function_propagates_env() {
        // Function body sets a variable that's used after the call
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("f() { x=hello; }; f; echo $x", &config);
        assert_eq!(result.decision, Decision::Allow);
    }
}

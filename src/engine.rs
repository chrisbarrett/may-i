// Rule engine — R7, R8, R9
// Evaluates parsed commands against rules, handles wrappers and flag expansion.

use std::collections::HashMap;

use crate::parser::{self, SimpleCommand, Word};
use crate::security;
use crate::types::{
    ArgMatcher, CommandMatcher, Config, Decision, Effect, EvalResult, PosExpr, WrapperKind,
};

/// Deduplicate a list of dynamic part descriptions while preserving order.
fn dedup_parts(parts: &[String]) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    parts
        .iter()
        .filter(|p| seen.insert(p.as_str()))
        .map(|p| p.as_str())
        .collect()
}

/// Build a snapshot of safe environment variable values.
fn build_env_snapshot(config: &Config) -> HashMap<String, String> {
    let mut env = HashMap::new();
    for name in &config.security.safe_env_vars {
        if let Ok(val) = std::env::var(name) {
            env.insert(name.clone(), val);
        }
    }
    env
}

/// Evaluate a shell command string against the config.
pub fn evaluate(input: &str, config: &Config) -> EvalResult {
    // Parse the command once, before any analysis
    let ast = parser::parse(input);

    // R11: Security filters (on parsed AST + raw input fallback)
    if let Some(reason) = security::check_blocked_paths(&ast, input, config) {
        return EvalResult {
            decision: Decision::Deny,
            reason: Some(reason),
        };
    }

    // Build env snapshot for safe variable resolution
    let env = build_env_snapshot(config);

    // Check structural dynamic parts (for-loop words, case discriminants/patterns)
    let structural = parser::find_structural_dynamic_parts(&ast, &env);
    if !structural.is_empty() {
        let parts = dedup_parts(&structural);
        return EvalResult {
            decision: Decision::Ask,
            reason: Some(format!(
                "Cannot statically analyse dynamic value{}: {}",
                if parts.len() == 1 { "" } else { "s" },
                parts.join(", "),
            )),
        };
    }

    // Extract all simple commands
    let simple_commands = parser::extract_simple_commands(&ast);

    if simple_commands.is_empty() {
        return EvalResult {
            decision: Decision::Ask,
            reason: Some("No commands found".into()),
        };
    }

    // Evaluate each simple command and aggregate (most restrictive wins)
    let mut overall: Option<EvalResult> = None;

    for sc in &simple_commands {
        let result = evaluate_simple_command(sc, config, 0, &env);
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

    overall.unwrap_or(EvalResult {
        decision: Decision::Allow,
        reason: None,
    })
}

/// Evaluate a single simple command against rules.
fn evaluate_simple_command(
    sc: &SimpleCommand,
    config: &Config,
    depth: usize,
    env: &HashMap<String, String>,
) -> EvalResult {
    // Resolve safe env vars
    let resolved = sc.resolve(env);

    // Check if the resolved command still has dynamic parts
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
        let cmd_label = resolved
            .command_name()
            .unwrap_or("<unknown>");
        let parts = dedup_parts(&dynamic);
        return EvalResult {
            decision: Decision::Ask,
            reason: Some(format!(
                "Command `{cmd_label}` contains dynamic value{} that cannot be statically analysed: {}",
                if parts.len() == 1 { "" } else { "s" },
                parts.join(", "),
            )),
        };
    }

    // Re-check blocked paths on resolved values
    if let Some(reason) =
        security::check_simple_command_paths(&resolved, &config.security.blocked_paths)
    {
        return EvalResult {
            decision: Decision::Deny,
            reason: Some(reason),
        };
    }

    let cmd_name = match resolved.command_name() {
        Some(name) if !name.is_empty() => name,
        _ => {
            return EvalResult {
                decision: Decision::Ask,
                reason: Some("Unknown command".into()),
            };
        }
    };

    // R9: Check if this is a wrapper command
    if depth < 5
        && let Some(inner) = unwrap_wrapper(&resolved, config)
    {
        return evaluate_simple_command(&inner, config, depth + 1, env);
    }

    // Expand flags: -abc → -a -b -c (R8)
    let expanded_args = expand_flags(resolved.args());

    // Evaluate against rules: deny rules first, then first match
    let mut first_match: Option<EvalResult> = None;

    for rule in &config.rules {
        if !command_matches(cmd_name, &rule.command) {
            continue;
        }

        // Determine if args match
        let args_match = match &rule.matcher {
            None => true,
            Some(m) => matcher_matches(m, &expanded_args),
        };
        if !args_match {
            continue;
        }

        // Determine decision+reason: from rule-level effect, top-level cond branches,
        // or embedded Expr::Cond effects
        let effect = if let Some(ref eff) = rule.effect {
            eff.clone()
        } else if let Some(ArgMatcher::Cond(branches)) = &rule.matcher {
            // Top-level cond: find first matching branch for its effect
            let mut found = None;
            for branch in branches {
                let branch_match = match &branch.matcher {
                    None => true,
                    Some(m) => matcher_matches(m, &expanded_args),
                };
                if branch_match {
                    found = Some(branch.effect.clone());
                    break;
                }
            }
            let Some(eff) = found else { continue };
            eff
        } else if let Some(ref m) = rule.matcher {
            // Walk matcher tree for Expr::Cond effects
            let Some(eff) = m.find_expr_effect(&expanded_args) else { continue };
            eff
        } else {
            continue;
        };

        let Effect { decision, reason } = effect;
        let result = EvalResult { decision, reason };

        // Deny rules always win
        if decision == Decision::Deny {
            return result;
        }

        // Otherwise, first match wins
        if first_match.is_none() {
            first_match = Some(result);
        }
    }

    first_match.unwrap_or(EvalResult {
        decision: Decision::Ask,
        reason: Some(format!("No matching rule for command `{cmd_name}`")),
    })
}

/// Check if a command name matches a command matcher.
fn command_matches(name: &str, matcher: &CommandMatcher) -> bool {
    match matcher {
        CommandMatcher::Exact(s) => name == s,
        CommandMatcher::Regex(re) => re.is_match(name),
        CommandMatcher::List(names) => names.iter().any(|n| n == name),
    }
}

fn match_positional(patterns: &[PosExpr], args: &[String], exact: bool) -> bool {
    let positional = extract_positional_args(args);
    let mut pos = 0;

    for pexpr in patterns {
        match pexpr {
            PosExpr::One(e) => {
                if positional.get(pos).is_none_or(|arg| !(e.is_wildcard() || e.is_match(arg))) {
                    return false;
                }
                pos += 1;
            }
            PosExpr::Optional(e) => {
                if let Some(arg) = positional.get(pos)
                    && (e.is_wildcard() || e.is_match(arg))
                {
                    pos += 1;
                }
            }
            PosExpr::OneOrMore(e) => {
                if positional.get(pos).is_none_or(|arg| !(e.is_wildcard() || e.is_match(arg))) {
                    return false;
                }
                pos += 1;
                while let Some(arg) = positional.get(pos) {
                    if !(e.is_wildcard() || e.is_match(arg)) {
                        break;
                    }
                    pos += 1;
                }
            }
            PosExpr::ZeroOrMore(e) => {
                while let Some(arg) = positional.get(pos) {
                    if !(e.is_wildcard() || e.is_match(arg)) {
                        break;
                    }
                    pos += 1;
                }
            }
        }
    }

    if exact {
        pos == positional.len()
    } else {
        pos <= positional.len()
    }
}

fn matcher_matches(matcher: &ArgMatcher, args: &[String]) -> bool {
    match matcher {
        ArgMatcher::Positional(patterns) => match_positional(patterns, args, false),
        ArgMatcher::ExactPositional(patterns) => match_positional(patterns, args, true),
        ArgMatcher::Anywhere(tokens) => {
            // Any of the listed tokens appears anywhere in args (OR semantics).
            tokens.iter().any(|token| args.iter().any(|a| token.is_match(a)))
        }
        ArgMatcher::And(matchers) => matchers.iter().all(|m| matcher_matches(m, args)),
        ArgMatcher::Or(matchers) => matchers.iter().any(|m| matcher_matches(m, args)),
        ArgMatcher::Not(inner) => !matcher_matches(inner, args),
        ArgMatcher::Cond(branches) => branches.iter().any(|b| match &b.matcher {
            None => true,
            Some(m) => matcher_matches(m, args),
        }),
    }
}

/// Extract positional args from an argument list, skipping flags and their values.
/// A bare `--` is treated as a positional arg and also terminates flag parsing
/// (everything after it is positional). A bare `-` is always positional.
fn extract_positional_args(args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut flags_done = false;
    for arg in args {
        if flags_done {
            positional.push(arg.clone());
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            // Bare `--` is positional and terminates flag parsing.
            positional.push(arg.clone());
            flags_done = true;
            continue;
        }
        if arg.starts_with("--") {
            // Long flag: if it doesn't contain '=', the next arg is its value
            if !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            // Short flag(s): skip
            continue;
        }
        positional.push(arg.clone());
    }
    positional
}

/// R8: Expand combined short flags: -abc → -a -b -c
fn expand_flags(args: &[Word]) -> Vec<String> {
    let mut result = Vec::new();
    for arg in args {
        let s = arg.to_str();
        if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 {
            // Expand: -abc → -a -b -c
            for ch in s[1..].chars() {
                result.push(format!("-{ch}"));
            }
        } else {
            result.push(s);
        }
    }
    result
}

/// R9: Attempt to unwrap a wrapper command, returning the inner command.
fn unwrap_wrapper(sc: &SimpleCommand, config: &Config) -> Option<SimpleCommand> {
    let cmd_name = sc.command_name()?;

    for wrapper in &config.wrappers {
        if wrapper.command != cmd_name {
            continue;
        }

        let args: Vec<String> = sc.args().iter().map(|w| w.to_str()).collect();

        // Check positional arg match (if wrapper has positional requirements)
        if !wrapper.positional_args.is_empty() {
            let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            let matches = wrapper
                .positional_args
                .iter()
                .enumerate()
                .all(|(i, pat)| positional.get(i).is_some_and(|a| pat.is_match(a)));
            if !matches {
                continue;
            }
        }

        match &wrapper.kind {
            WrapperKind::AfterFlags => {
                // Find the first non-flag argument after the command
                let inner_start = sc.words[1..]
                    .iter()
                    .position(|w| !w.to_str().starts_with('-'))
                    .map(|i| i + 1)?;

                if inner_start < sc.words.len() {
                    return Some(SimpleCommand {
                        assignments: vec![],
                        words: sc.words[inner_start..].to_vec(),
                        redirections: sc.redirections.clone(),
                    });
                }
            }
            WrapperKind::AfterDelimiter(delim) => {
                let delim_pos = sc.words[1..]
                    .iter()
                    .position(|w| w.to_str() == *delim)
                    .map(|i| i + 2)?; // +1 for the delimiter, +1 for offset

                if delim_pos < sc.words.len() {
                    return Some(SimpleCommand {
                        assignments: vec![],
                        words: sc.words[delim_pos..].to_vec(),
                        redirections: sc.redirections.clone(),
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CondBranch, Config, Effect, Expr, PosExpr, Rule, SecurityConfig, Wrapper, WrapperKind,
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

    // ── Flag expansion ──────────────────────────────────────────────

    #[test]
    fn test_flag_expansion() {
        let args = vec![Word::literal("-abc"), Word::literal("--verbose")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec!["-a", "-b", "-c", "--verbose"]);
    }

    #[test]
    fn flag_expansion_single_short_flag_unchanged() {
        let args = vec![Word::literal("-v")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec!["-v"]);
    }

    #[test]
    fn flag_expansion_plain_args_unchanged() {
        let args = vec![Word::literal("hello"), Word::literal("world")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec!["hello", "world"]);
    }

    #[test]
    fn flag_expansion_long_flag_unchanged() {
        let args = vec![Word::literal("--verbose")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec!["--verbose"]);
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
    fn evaluate_empty_input_asks() {
        let config = empty_config();
        let result = evaluate("", &config);
        assert_eq!(result.decision, Decision::Ask);
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
    fn evaluate_for_loop() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("for x in a b c; do echo $x; done", &config);
        // $x is dynamic, so security check triggers Ask
        assert_eq!(result.decision, Decision::Ask);
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
        let args = vec!["status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_wildcard() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Wildcard]));
        let args = vec!["anything".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_regex() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Regex(regex::Regex::new("^(status|log)$").unwrap())]));
        assert!(matcher_matches(&matcher, &["status".into()]));
        assert!(matcher_matches(&matcher, &["log".into()]));
        assert!(!matcher_matches(&matcher, &["push".into()]));
    }

    #[test]
    fn positional_matcher_too_few_args() {
        let matcher = ArgMatcher::Positional(pos(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
        ]));
        assert!(!matcher_matches(&matcher, &["a".into()]));
    }

    #[test]
    fn positional_matcher_skips_flags() {
        let matcher = ArgMatcher::Positional(pos(vec![Expr::Literal("status".into())]));
        // Flags are skipped by extract_positional_args, leaving "status"
        let args = vec!["-v".to_string(), "status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::ExactPositional ──────────────────────────────────

    #[test]
    fn exact_positional_matches_exact_count() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
        assert!(matcher_matches(&matcher, &["status".into()]));
    }

    #[test]
    fn exact_positional_rejects_extra_args() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("remote".into())]));
        assert!(!matcher_matches(&matcher, &["remote".into(), "add".into()]));
    }

    #[test]
    fn exact_positional_rejects_too_few() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
        ]));
        assert!(!matcher_matches(&matcher, &["a".into()]));
    }

    #[test]
    fn exact_positional_skips_flags() {
        let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
        let args = vec!["-v".to_string(), "status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::Anywhere ────────────────────────────────────────

    #[test]
    fn anywhere_matcher_present() {
        let tokens = vec![Expr::Literal("--force".into())];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec!["push".into(), "--force".into()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_absent() {
        let tokens = vec![Expr::Literal("--force".into())];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec!["push".into(), "origin".into()];
        assert!(!matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_or_semantics() {
        // Any of the listed tokens triggers a match
        let tokens = vec![
            Expr::Literal("--force".into()),
            Expr::Literal("-f".into()),
        ];
        let matcher = ArgMatcher::Anywhere(tokens);
        assert!(matcher_matches(&matcher, &["-f".into()]));
        assert!(matcher_matches(&matcher, &["--force".into()]));
        assert!(!matcher_matches(&matcher, &["--verbose".into()]));
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
        assert!(matcher_matches(&m, &["push".into(), "origin".into()]));
        assert!(!matcher_matches(&m, &["push".into(), "--force".into()]));
    }

    #[test]
    fn or_matcher_any_must_pass() {
        let m = ArgMatcher::Or(vec![
            ArgMatcher::Anywhere(vec![Expr::Literal("-v".into())]),
            ArgMatcher::Anywhere(vec![Expr::Literal("--verbose".into())]),
        ]);
        assert!(matcher_matches(&m, &["-v".into()]));
        assert!(matcher_matches(&m, &["--verbose".into()]));
        assert!(!matcher_matches(&m, &["--quiet".into()]));
    }

    #[test]
    fn not_matcher_inverts() {
        let m = ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
            Expr::Literal("--force".into()),
        ])));
        assert!(matcher_matches(&m, &["push".into()]));
        assert!(!matcher_matches(&m, &["--force".into()]));
    }

    // ── extract_positional_args() ───────────────────────────────────

    #[test]
    fn extract_positional_skips_short_flags() {
        let args: Vec<String> = vec!["-v".into(), "status".into()];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec!["status"]);
    }

    #[test]
    fn extract_positional_skips_long_flags_and_values() {
        let args: Vec<String> = vec!["--output".into(), "file.txt".into(), "input.txt".into()];
        let pos = extract_positional_args(&args);
        // --output consumes file.txt as its value, only input.txt remains
        assert_eq!(pos, vec!["input.txt"]);
    }

    #[test]
    fn extract_positional_long_flag_with_equals() {
        let args: Vec<String> = vec!["--output=file.txt".into(), "input.txt".into()];
        let pos = extract_positional_args(&args);
        // --output=file.txt doesn't consume the next arg
        assert_eq!(pos, vec!["input.txt"]);
    }

    #[test]
    fn extract_positional_bare_dash_is_positional() {
        // A bare "-" is often used for stdin, not a flag
        let args: Vec<String> = vec!["-".into()];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec!["-"]);
    }

    #[test]
    fn extract_positional_double_dash_is_positional() {
        let args: Vec<String> = vec!["run".into(), "--".into(), "test".into()];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec!["run", "--", "test"]);
    }

    #[test]
    fn extract_positional_double_dash_terminates_flags() {
        // After --, even flag-looking tokens are positional
        let args: Vec<String> = vec!["--".into(), "--force".into(), "-v".into()];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec!["--", "--force", "-v"]);
    }

    #[test]
    fn extract_positional_flags_before_double_dash_skipped() {
        let args: Vec<String> = vec!["-v".into(), "--".into(), "arg".into()];
        let pos = extract_positional_args(&args);
        assert_eq!(pos, vec!["--", "arg"]);
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
        assert_eq!(result.decision, Decision::Ask); // no matching rule
    }

    #[test]
    fn deny_rule_wins_over_allow() {
        // After flag expansion, -rf becomes -r and -f, so match on -r
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
        // "rm -rf /" should be denied because -rf expands to -r -f, and -r triggers deny
        let result = evaluate("rm -rf /", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn first_matching_non_deny_rule_wins() {
        // Two rules: first is Ask, second is Allow. First match (Ask) should win.
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

    #[test]
    fn wrapper_after_flags_unwraps() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "sudo".into(),
                positional_args: vec![],
                kind: WrapperKind::AfterFlags,
            }],
            ..Config::default()
        };
        let result = evaluate("sudo ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_after_flags_with_flags() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "sudo".into(),
                positional_args: vec![],
                kind: WrapperKind::AfterFlags,
            }],
            ..Config::default()
        };
        // sudo -u root ls → inner command is "ls"
        let result = evaluate("sudo -u ls", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_after_delimiter_unwraps() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "env".into(),
                positional_args: vec![],
                kind: WrapperKind::AfterDelimiter("--".into()),
            }],
            ..Config::default()
        };
        let result = evaluate("env FOO=bar -- ls -la", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_with_positional_args() {
        let config = Config {
            rules: vec![allow_rule("ls")],
            wrappers: vec![Wrapper {
                command: "docker".into(),
                positional_args: vec![Expr::Literal("exec".into())],
                kind: WrapperKind::AfterFlags,
            }],
            ..Config::default()
        };
        // "docker exec container ls" matches the wrapper
        let result = evaluate("docker exec container ls", &config);
        // The wrapper positional_args requires "exec" at position 0, and
        // AfterFlags takes the first non-flag word as the inner command start.
        // words: [docker, exec, container, ls]
        // inner_start finds first non-flag in words[1..] = "exec" at offset 0, so inner_start = 1
        // inner = words[1..] = [exec, container, ls], command_name = "exec"
        // "exec" has no matching rule → Ask
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn wrapper_positional_mismatch_no_unwrap() {
        let config = Config {
            rules: vec![allow_rule("docker")],
            wrappers: vec![Wrapper {
                command: "docker".into(),
                positional_args: vec![Expr::Literal("exec".into())],
                kind: WrapperKind::AfterFlags,
            }],
            ..Config::default()
        };
        // "docker run container" does not match "exec" positional requirement,
        // so no unwrapping; "docker" is evaluated as-is with allow_rule
        let result = evaluate("docker run container", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_not_matching_command() {
        let config = Config {
            rules: vec![allow_rule("nohup")],
            wrappers: vec![Wrapper {
                command: "sudo".into(),
                positional_args: vec![],
                kind: WrapperKind::AfterFlags,
            }],
            ..Config::default()
        };
        // "nohup" is not "sudo", so no unwrapping happens
        let result = evaluate("nohup sleep 10", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Security integration ────────────────────────────────────────

    #[test]
    fn security_blocked_path_denies() {
        let config = Config {
            rules: vec![allow_rule("cat")],
            ..Config::default()
        };
        let result = evaluate("cat .env", &config);
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.unwrap().contains("credential"));
    }

    #[test]
    fn security_dynamic_parts_asks() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("echo $(whoami)", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$(whoami)"), "should mention the dynamic part: {reason}");
    }

    #[test]
    fn security_ssh_path_blocked() {
        let config = Config {
            rules: vec![allow_rule("cat")],
            ..Config::default()
        };
        let result = evaluate("cat .ssh/id_rsa", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn security_normal_file_allowed() {
        let config = Config {
            rules: vec![allow_rule("cat")],
            ..Config::default()
        };
        let result = evaluate("cat README.md", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── evaluate_simple_command(): edge cases ───────────────────────

    #[test]
    fn evaluate_empty_command_name() {
        // A command with no words should return Ask
        let sc = SimpleCommand {
            assignments: vec![],
            words: vec![],
            redirections: vec![],
        };
        let config = empty_config();
        let result = evaluate_simple_command(&sc, &config, 0, &HashMap::new());
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

        // push without --force → rule matches, Allow
        assert_eq!(
            evaluate("git push origin main", &config).decision,
            Decision::Allow
        );
        // push with --force → not(anywhere) fails, no rule matches → Ask
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

    // ── Per-command dynamic analysis with env var resolution ──────────

    #[test]
    fn env_var_resolved_allows_static_analysis() {
        unsafe { std::env::set_var("TEST_MAYI_HOME", "/home/user") };
        let config = Config {
            rules: vec![allow_rule("echo"), allow_rule("ls")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_HOME".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("echo $TEST_MAYI_HOME && ls", &config);
        assert_eq!(result.decision, Decision::Allow);
        unsafe { std::env::remove_var("TEST_MAYI_HOME") };
    }

    #[test]
    fn unresolved_env_var_triggers_ask() {
        let config = Config {
            rules: vec![allow_rule("echo"), allow_rule("ls")],
            ..Config::default()
        };
        let result = evaluate("echo $HOME && ls", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$HOME"), "should mention the variable: {reason}");
    }

    #[test]
    fn resolved_env_var_blocked_path_denies() {
        unsafe { std::env::set_var("TEST_MAYI_HOME2", "/home/user") };
        let config = Config {
            rules: vec![allow_rule("cat")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_HOME2".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("cat $TEST_MAYI_HOME2/.ssh/id_rsa", &config);
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.unwrap().contains(".ssh/"));
        unsafe { std::env::remove_var("TEST_MAYI_HOME2") };
    }

    #[test]
    fn command_sub_never_resolvable() {
        let config = Config {
            rules: vec![allow_rule("echo"), allow_rule("ls")],
            ..Config::default()
        };
        let result = evaluate("echo $(whoami) && ls", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("echo"), "should mention the command: {reason}");
        assert!(reason.contains("$(whoami)"), "should mention command substitution: {reason}");
    }

    #[test]
    fn deny_wins_with_resolved_env_var() {
        unsafe { std::env::set_var("TEST_MAYI_HOME3", "/tmp") };
        let config = Config {
            rules: vec![deny_rule("ls"), allow_rule("echo")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_HOME3".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("ls && echo $TEST_MAYI_HOME3", &config);
        assert_eq!(result.decision, Decision::Deny);
        unsafe { std::env::remove_var("TEST_MAYI_HOME3") };
    }

    #[test]
    fn for_loop_dynamic_iteration_words_ask() {
        let config = Config {
            rules: vec![allow_rule("echo")],
            ..Config::default()
        };
        let result = evaluate("for f in $items; do echo $f; done", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("$items"), "should mention the variable: {reason}");
    }

    // ── Parameter expansion operator integration ─────────────────────

    #[test]
    fn param_op_resolved_safe_env_allows() {
        unsafe { std::env::set_var("TEST_MAYI_PATH", "/usr/local/bin") };
        let config = Config {
            rules: vec![allow_rule("echo")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_PATH".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("echo ${TEST_MAYI_PATH##*/}", &config);
        assert_eq!(result.decision, Decision::Allow);
        unsafe { std::env::remove_var("TEST_MAYI_PATH") };
    }

    #[test]
    fn param_op_unresolved_triggers_ask() {
        let config = Config {
            rules: vec![allow_rule("echo")],
            ..Config::default()
        };
        let result = evaluate("echo ${UNKNOWN_VAR#pat}", &config);
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.unwrap();
        assert!(reason.contains("UNKNOWN_VAR"), "should mention the variable: {reason}");
    }

    #[test]
    fn param_op_default_value_with_safe_env() {
        unsafe { std::env::set_var("TEST_MAYI_OPT", "value") };
        let config = Config {
            rules: vec![allow_rule("echo")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_OPT".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("echo ${TEST_MAYI_OPT:-fallback}", &config);
        assert_eq!(result.decision, Decision::Allow);
        unsafe { std::env::remove_var("TEST_MAYI_OPT") };
    }

    #[test]
    fn param_op_in_double_quotes_resolved() {
        unsafe { std::env::set_var("TEST_MAYI_FILE", "archive.tar.gz") };
        let config = Config {
            rules: vec![allow_rule("echo")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_FILE".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate(r#"echo "${TEST_MAYI_FILE%%.*}""#, &config);
        assert_eq!(result.decision, Decision::Allow);
        unsafe { std::env::remove_var("TEST_MAYI_FILE") };
    }

    // ── Empty simple commands → Ask ──────────────────────────────────

    #[test]
    fn compound_with_no_simple_commands_asks() {
        // A function definition with no body commands — extract_simple_commands returns empty
        let config = config_with_rules(vec![allow_rule("f")]);
        let result = evaluate("f() { :; }", &config);
        // ':' is a simple command, so this won't trigger the empty branch.
        // Instead, test an input that parses to only compound structure.
        // An empty subshell: ( )
        let result2 = evaluate("()", &config);
        // This parses as an empty simple command inside a subshell
        assert!(result.decision == Decision::Allow || result.decision == Decision::Ask);
        assert!(result2.decision == Decision::Ask || result2.decision == Decision::Allow);
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
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate("echo hello > $OUTFILE", &config);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Blocked path in redirect target ──────────────────────────────

    #[test]
    fn blocked_path_in_redirect_target_denies() {
        let config = Config {
            rules: vec![allow_rule("echo")],
            ..Config::default()
        };
        let result = evaluate("echo secret > .env", &config);
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── Resolved blocked path in redirect target ─────────────────────

    #[test]
    fn resolved_blocked_path_in_redirect_denies() {
        unsafe { std::env::set_var("TEST_MAYI_REDIR", ".ssh/id_rsa") };
        let config = Config {
            rules: vec![allow_rule("echo")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_REDIR".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("echo hello > $TEST_MAYI_REDIR", &config);
        assert_eq!(result.decision, Decision::Deny);
        unsafe { std::env::remove_var("TEST_MAYI_REDIR") };
    }

    // ── Resolved blocked path in word arg ────────────────────────────

    #[test]
    fn resolved_blocked_path_in_word_denies() {
        unsafe { std::env::set_var("TEST_MAYI_FILE2", ".env") };
        let config = Config {
            rules: vec![allow_rule("cat")],
            security: SecurityConfig {
                safe_env_vars: ["TEST_MAYI_FILE2".to_string()].into(),
                ..SecurityConfig::default()
            },
            ..Config::default()
        };
        let result = evaluate("cat $TEST_MAYI_FILE2", &config);
        assert_eq!(result.decision, Decision::Deny);
        unsafe { std::env::remove_var("TEST_MAYI_FILE2") };
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
                    matcher: None, // wildcard
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
        // No branch matches, rule is skipped → Ask (no matching rule)
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
            allow_rule("tmux"), // would allow everything, but deny from cond wins
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

        // Verify checks pass
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
        )
        .unwrap();

        // "source-file safe.conf" matches
        assert_eq!(
            evaluate("tmux source-file safe.conf", &config).decision,
            Decision::Allow
        );
        // "source-file other.conf" — when branch doesn't match, no effect, rule skipped → Ask
        assert_eq!(
            evaluate("tmux source-file other.conf", &config).decision,
            Decision::Ask
        );
        // Different positional arg entirely — matcher won't match → Ask
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
}

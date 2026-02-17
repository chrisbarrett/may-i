// Rule engine — R7, R8, R9
// Evaluates parsed commands against rules, handles wrappers and flag expansion.

use std::collections::HashMap;

use crate::parser::{self, SimpleCommand, Word};
use crate::security;
use crate::types::{ArgMatcher, CommandMatcher, Config, Decision, EvalResult, Pattern, WrapperKind};

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
    let mut overall = EvalResult {
        decision: Decision::Allow,
        reason: None,
    };

    for sc in &simple_commands {
        let result = evaluate_simple_command(sc, config, 0, &env);
        if result.decision == Decision::Deny {
            return result;
        }
        if result.decision.most_restrictive(overall.decision) != overall.decision {
            overall = result;
        }
    }

    overall
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

        let args_match = match &rule.matcher {
            None => true,
            Some(m) => matcher_matches(m, &expanded_args),
        };
        if !args_match {
            continue;
        }

        // Rule matches
        let result = EvalResult {
            decision: rule.decision,
            reason: rule.reason.clone(),
        };

        // Deny rules always win
        if rule.decision == Decision::Deny {
            return result;
        }

        // Otherwise, first match wins
        if first_match.is_none() {
            first_match = Some(result);
        }
    }

    first_match.unwrap_or(EvalResult {
        decision: Decision::Ask,
        reason: Some("No matching rule".into()),
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

fn match_positional(patterns: &[Pattern], args: &[String], exact: bool) -> bool {
    let positional = extract_positional_args(args);
    if exact {
        if patterns.len() != positional.len() {
            return false;
        }
    } else if patterns.len() > positional.len() {
        return false;
    }
    patterns.iter().enumerate().all(|(i, pat)| {
        pat.is_wildcard() || positional.get(i).is_some_and(|arg| pat.is_match(arg))
    })
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
    }
}

/// Extract positional args from an argument list, skipping flags and their values.
/// Heuristic: a `--flag` token consumes the next non-flag-looking token as its value.
fn extract_positional_args(args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
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
    use crate::types::{Config, Pattern, Rule, SecurityConfig, Wrapper, WrapperKind};

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
            decision: Decision::Allow,
            reason: Some("allowed".into()),
            examples: vec![],
        }
    }

    fn deny_rule(cmd: &str) -> Rule {
        Rule {
            command: CommandMatcher::Exact(cmd.to_string()),
            matcher: None,
            decision: Decision::Deny,
            reason: Some("denied".into()),
            examples: vec![],
        }
    }

    fn ask_rule(cmd: &str) -> Rule {
        Rule {
            command: CommandMatcher::Exact(cmd.to_string()),
            matcher: None,
            decision: Decision::Ask,
            reason: Some("ask".into()),
            examples: vec![],
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
        assert_eq!(result.reason.as_deref(), Some("No matching rule"));
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
        let patterns = vec![Pattern::new("status").unwrap()];
        let matcher = ArgMatcher::Positional(patterns);
        let args = vec!["status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_wildcard() {
        let patterns = vec![Pattern::new("*").unwrap()];
        let matcher = ArgMatcher::Positional(patterns);
        let args = vec!["anything".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn positional_matcher_regex() {
        let patterns = vec![Pattern::new("^(status|log)$").unwrap()];
        let matcher = ArgMatcher::Positional(patterns);
        assert!(matcher_matches(&matcher, &["status".into()]));
        assert!(matcher_matches(&matcher, &["log".into()]));
        assert!(!matcher_matches(&matcher, &["push".into()]));
    }

    #[test]
    fn positional_matcher_too_few_args() {
        let patterns = vec![
            Pattern::new("a").unwrap(),
            Pattern::new("b").unwrap(),
        ];
        let matcher = ArgMatcher::Positional(patterns);
        assert!(!matcher_matches(&matcher, &["a".into()]));
    }

    #[test]
    fn positional_matcher_skips_flags() {
        let patterns = vec![Pattern::new("status").unwrap()];
        let matcher = ArgMatcher::Positional(patterns);
        // Flags are skipped by extract_positional_args, leaving "status"
        let args = vec!["-v".to_string(), "status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::ExactPositional ──────────────────────────────────

    #[test]
    fn exact_positional_matches_exact_count() {
        let patterns = vec![Pattern::new("status").unwrap()];
        let matcher = ArgMatcher::ExactPositional(patterns);
        assert!(matcher_matches(&matcher, &["status".into()]));
    }

    #[test]
    fn exact_positional_rejects_extra_args() {
        let patterns = vec![Pattern::new("remote").unwrap()];
        let matcher = ArgMatcher::ExactPositional(patterns);
        assert!(!matcher_matches(&matcher, &["remote".into(), "add".into()]));
    }

    #[test]
    fn exact_positional_rejects_too_few() {
        let patterns = vec![
            Pattern::new("a").unwrap(),
            Pattern::new("b").unwrap(),
        ];
        let matcher = ArgMatcher::ExactPositional(patterns);
        assert!(!matcher_matches(&matcher, &["a".into()]));
    }

    #[test]
    fn exact_positional_skips_flags() {
        let patterns = vec![Pattern::new("status").unwrap()];
        let matcher = ArgMatcher::ExactPositional(patterns);
        let args = vec!["-v".to_string(), "status".to_string()];
        assert!(matcher_matches(&matcher, &args));
    }

    // ── ArgMatcher::Anywhere ────────────────────────────────────────

    #[test]
    fn anywhere_matcher_present() {
        let tokens = vec![Pattern::new("--force").unwrap()];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec!["push".into(), "--force".into()];
        assert!(matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_absent() {
        let tokens = vec![Pattern::new("--force").unwrap()];
        let matcher = ArgMatcher::Anywhere(tokens);
        let args = vec!["push".into(), "origin".into()];
        assert!(!matcher_matches(&matcher, &args));
    }

    #[test]
    fn anywhere_matcher_or_semantics() {
        // Any of the listed tokens triggers a match
        let tokens = vec![
            Pattern::new("--force").unwrap(),
            Pattern::new("-f").unwrap(),
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
            ArgMatcher::Positional(vec![Pattern::new("push").unwrap()]),
            ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                Pattern::new("--force").unwrap(),
            ]))),
        ]);
        assert!(matcher_matches(&m, &["push".into(), "origin".into()]));
        assert!(!matcher_matches(&m, &["push".into(), "--force".into()]));
    }

    #[test]
    fn or_matcher_any_must_pass() {
        let m = ArgMatcher::Or(vec![
            ArgMatcher::Anywhere(vec![Pattern::new("-v").unwrap()]),
            ArgMatcher::Anywhere(vec![Pattern::new("--verbose").unwrap()]),
        ]);
        assert!(matcher_matches(&m, &["-v".into()]));
        assert!(matcher_matches(&m, &["--verbose".into()]));
        assert!(!matcher_matches(&m, &["--quiet".into()]));
    }

    #[test]
    fn not_matcher_inverts() {
        let m = ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
            Pattern::new("--force").unwrap(),
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

    // ── Rule matching integration ───────────────────────────────────

    #[test]
    fn rule_with_positional_matcher() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(vec![
                Pattern::new("status").unwrap(),
            ])),
            decision: Decision::Allow,
            reason: None,
            examples: vec![],
        };
        let config = config_with_rules(vec![rule]);
        let result = evaluate("git status", &config);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn rule_with_positional_no_match() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: Some(ArgMatcher::Positional(vec![
                Pattern::new("status").unwrap(),
            ])),
            decision: Decision::Allow,
            reason: None,
            examples: vec![],
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
                    Pattern::new("-r").unwrap(),
                ])),
                decision: Decision::Deny,
                reason: Some("dangerous".into()),
                examples: vec![],
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
                decision: Decision::Ask,
                reason: Some("first".into()),
                examples: vec![],
            },
            Rule {
                command: CommandMatcher::Exact("git".into()),
                matcher: None,
                decision: Decision::Allow,
                reason: Some("second".into()),
                examples: vec![],
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
            decision: Decision::Allow,
            reason: None,
            examples: vec![],
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
            decision: Decision::Allow,
            reason: None,
            examples: vec![],
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
                positional_args: vec![Pattern::new("exec").unwrap()],
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
                positional_args: vec![Pattern::new("exec").unwrap()],
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
                ArgMatcher::Positional(vec![Pattern::new("push").unwrap()]),
                ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                    Pattern::new("--force").unwrap(),
                    Pattern::new("-f").unwrap(),
                ]))),
            ])),
            decision: Decision::Allow,
            reason: Some("safe push".into()),
            examples: vec![],
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
                Pattern::new("^-r$").unwrap(),
            ])),
            decision: Decision::Allow,
            reason: None,
            examples: vec![],
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
}

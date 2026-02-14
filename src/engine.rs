// Rule engine — R7, R8, R9
// Evaluates parsed commands against rules, handles wrappers and flag expansion.

use crate::config::{CommandMatcher, Config, Example};
use crate::parser::{self, SimpleCommand, Word};
use crate::security;

/// The three possible authorization decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl Decision {
    /// Returns the more restrictive of two decisions.
    pub fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Decision::Deny, _) | (_, Decision::Deny) => Decision::Deny,
            (Decision::Ask, _) | (_, Decision::Ask) => Decision::Ask,
            _ => Decision::Allow,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Ask => write!(f, "ask"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}

/// A configured authorization rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub command: CommandMatcher,
    pub matchers: Vec<ArgMatcher>,
    pub decision: Decision,
    pub reason: Option<String>,
    pub examples: Vec<Example>,
}

/// Argument matching strategies.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    /// Match positional args by position (skip flags). "*" = any value.
    Positional(Vec<String>),
    /// Token appears anywhere in argv.
    Anywhere(Vec<String>),
    /// Rule matches only if these patterns are NOT found.
    Forbidden(Vec<String>),
}

/// Wrapper configuration for command unwrapping.
#[derive(Debug, Clone)]
pub struct Wrapper {
    pub command: String,
    pub positional_args: Vec<String>,
    pub kind: WrapperKind,
}

#[derive(Debug, Clone)]
pub enum WrapperKind {
    /// Inner command starts after all flags (e.g., nohup, env).
    AfterFlags,
    /// Inner command starts after a specific delimiter (e.g., mise exec --).
    AfterDelimiter(String),
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
}

/// Evaluate a shell command string against the config.
pub fn evaluate(input: &str, config: &Config) -> EvalResult {
    // R11: Security filters first
    if let Some(reason) = security::check_blocked_paths(input, config) {
        return EvalResult {
            decision: Decision::Deny,
            reason: Some(reason),
        };
    }

    // Parse the command
    let ast = parser::parse(input);

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
        let result = evaluate_simple_command(sc, config, 0);
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
fn evaluate_simple_command(sc: &SimpleCommand, config: &Config, depth: usize) -> EvalResult {
    let cmd_name = match sc.command_name() {
        Some(name) if !name.is_empty() => name,
        _ => {
            return EvalResult {
                decision: Decision::Ask,
                reason: Some("Unknown command".into()),
            };
        }
    };

    // R9: Check if this is a wrapper command
    if depth < 5 {
        if let Some(inner) = unwrap_wrapper(sc, config) {
            return evaluate_simple_command(&inner, config, depth + 1);
        }
    }

    // Expand flags: -abc → -a -b -c (R8)
    let expanded_args = expand_flags(sc.args());

    // Evaluate against rules: deny rules first, then first match
    let mut first_match: Option<EvalResult> = None;

    for rule in &config.rules {
        if !command_matches(cmd_name, &rule.command) {
            continue;
        }

        if !matchers_match(&rule.matchers, &expanded_args) {
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
        CommandMatcher::Regex(pattern) => {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(name))
                .unwrap_or(false)
        }
        CommandMatcher::List(names) => names.iter().any(|n| n == name),
    }
}

/// Check if all matchers match the given args.
fn matchers_match(matchers: &[ArgMatcher], args: &[String]) -> bool {
    if matchers.is_empty() {
        return true;
    }
    matchers.iter().all(|m| matcher_matches(m, args))
}

fn matcher_matches(matcher: &ArgMatcher, args: &[String]) -> bool {
    match matcher {
        ArgMatcher::Positional(patterns) => {
            let positional = extract_positional_args(args);

            if patterns.len() > positional.len() {
                return false;
            }

            patterns.iter().enumerate().all(|(i, pat)| {
                if pat == "*" {
                    true
                } else if pat.starts_with('^') {
                    regex::Regex::new(pat)
                        .map(|re| re.is_match(&positional[i]))
                        .unwrap_or(false)
                } else {
                    positional.get(i).is_some_and(|arg| arg == pat)
                }
            })
        }
        ArgMatcher::Anywhere(tokens) => {
            // Any of the listed tokens appears anywhere in args (OR semantics).
            // Multiple Anywhere matchers on one rule are AND-ed at the outer level.
            tokens.iter().any(|token| {
                if token.starts_with('^') {
                    regex::Regex::new(token)
                        .map(|re| args.iter().any(|a| re.is_match(a)))
                        .unwrap_or(false)
                } else {
                    args.iter().any(|a| a == token)
                }
            })
        }
        ArgMatcher::Forbidden(tokens) => {
            // Rule matches if NONE of the forbidden tokens are found
            tokens.iter().all(|token| !args.iter().any(|a| a == token))
        }
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
                .all(|(i, pat)| positional.get(i).is_some_and(|a| *a == pat));
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

/// Run all embedded examples from config rules, return (passed, failed, errors).
pub fn check_examples(config: &Config) -> Vec<ExampleResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for example in &rule.examples {
            let eval = evaluate(&example.command, config);
            results.push(ExampleResult {
                command: example.command.clone(),
                expected: example.expected,
                actual: eval.decision,
                passed: eval.decision == example.expected,
            });
        }
    }

    results
}

#[derive(Debug)]
pub struct ExampleResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_expansion() {
        let args = vec![Word::literal("-abc"), Word::literal("--verbose")];
        let expanded = expand_flags(&args);
        assert_eq!(expanded, vec!["-a", "-b", "-c", "--verbose"]);
    }

    #[test]
    fn test_decision_most_restrictive() {
        assert_eq!(Decision::Allow.most_restrictive(Decision::Ask), Decision::Ask);
        assert_eq!(Decision::Ask.most_restrictive(Decision::Deny), Decision::Deny);
        assert_eq!(Decision::Allow.most_restrictive(Decision::Allow), Decision::Allow);
    }
}

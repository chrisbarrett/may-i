// Config validation — run embedded checks against the engine.

use may_i_core::ast::Config;
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser::{self as parser, Command, Word, WordPart};
use crate::trace::TraceEntry;
use crate::EvalResult;

/// Result of evaluating a single embedded check.
#[derive(Debug)]
pub struct CheckResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub context: ContextFacts,
    pub reason: Option<String>,
    pub trace: Vec<TraceEntry>,
    pub location: Option<String>,
}

/// Evaluate a simple shell command string using the v2 evaluator.
/// For now, this only handles simple commands (not compound commands).
fn evaluate_simple(input: &str, config: &Config, context: &ContextFacts) -> EvalResult {
    let cmd = parser::parse(input);
    
    match cmd {
        Command::Simple(sc) if !sc.words.is_empty() => {
            // Extract command name from first word
            let cmd_name = word_to_string(&sc.words[0]);
            // Extract arguments
            let args: Vec<String> = sc.words[1..].iter().map(word_to_string).collect();
            
            crate::eval::evaluate(&cmd_name, &args, config, context)
        }
        Command::Simple(_) => {
            // Assignment-only command or empty
            EvalResult::new(Decision::Allow, None)
        }
        _ => {
            // Compound commands - for now return Ask
            // Full compound evaluation will be implemented in task 14
            EvalResult::new(Decision::Ask, Some("Compound commands not yet supported in checks".into()))
        }
    }
}

/// Convert a Word to a string (taking the first literal part or empty string)
fn word_to_string(word: &Word) -> String {
    word.parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(s) => s.clone(),
            WordPart::SingleQuoted(s) => s.clone(),
            WordPart::DoubleQuoted(parts) => parts
                .iter()
                .map(|p| match p {
                    WordPart::Literal(s) => s.clone(),
                    _ => String::new(),
                })
                .collect(),
            _ => String::new(),
        })
        .collect()
}

/// Run all embedded checks from config rules and compare against expected decisions.
pub fn run_checks(config: &Config) -> Vec<CheckResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for check in &rule.checks {
            let eval = evaluate_simple(&check.command, config, &check.context);
            let location = None; // TODO: Add source info back when available
            results.push(CheckResult {
                command: check.command.clone(),
                expected: check.expected,
                actual: eval.decision,
                passed: eval.decision == check.expected,
                context: check.context.clone(),
                reason: eval.reason,
                trace: eval.trace,
                location,
            });
        }
    }

    for check in &config.checks {
        let eval = evaluate_simple(&check.command, config, &check.context);
        let location = None; // TODO: Add source info back when available
        results.push(CheckResult {
            command: check.command.clone(),
            expected: check.expected,
            actual: eval.decision,
            passed: eval.decision == check.expected,
            context: check.context.clone(),
            reason: eval.reason,
            trace: eval.trace,
            location,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{Check, Config, Effect, Rule};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::{Decision, Span};

    fn create_test_rule(name: &str, effect: Effect) -> Rule {
        use may_i_core::ast::Spanned;
        Rule {
            command_effect: Spanned::new(Effect::CommandPattern(CommandPattern::Literal(name.into())), Span::new(0, 0)),
            effects: vec![Spanned::new(effect, Span::new(0, 0))],
            checks: vec![],
            span: Span::new(0, 0),
        }
    }

    #[test]
    fn run_checks_passing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Allow(Some("listed".into())),
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls -la".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Allow);
    }

    #[test]
    fn run_checks_failing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Deny(Some("denied".into())),
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Deny);
    }
}

// Config validation — run embedded examples against the engine.

use crate::engine;
use crate::types::{Config, Decision};

/// Result of evaluating a single embedded example.
#[derive(Debug)]
pub struct ExampleResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
}

/// Run all embedded examples from config rules and compare against expected decisions.
pub fn check_examples(config: &Config) -> Vec<ExampleResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for example in &rule.examples {
            let eval = engine::evaluate(&example.command, config);
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

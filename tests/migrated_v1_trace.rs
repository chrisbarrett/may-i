// Trace-render snapshot tests for the v1 config fixture.
//
// Each test case loads the v1 fixture (transparently migrated to current
// syntax), evaluates a command, and snapshots the rendered trace.
// Two variants per case: stripped (human-readable) and raw (with ANSI codes).

use std::path::Path;

use serde::Deserialize;

use may_i::cmd_eval::evaluate_with_colorization;
use may_i::output::{self, EvalOutput};
use may_i::pipeline::CommandPipeline;
use may_i::trust::InvocationTrust;
use may_i_config::LoadResult;

#[derive(Deserialize)]
struct Cases {
    case: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    command: String,
    #[serde(default)]
    facts: Vec<String>,
}

fn fixture_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v1")
        .leak()
}

fn load_cases() -> Vec<Case> {
    let content = std::fs::read_to_string(fixture_dir().join("cases.toml"))
        .expect("failed to read cases.toml");
    let cases: Cases = toml::from_str(&content).expect("failed to parse cases.toml");
    cases.case
}

fn load_config() -> LoadResult {
    let config_path = fixture_dir().join("config.lisp");
    let mut loaded = may_i_config::load(&config_path).expect("failed to load v1 fixture config");
    let resolved_rules =
        may_i_config::resolve::validate_and_resolve(&loaded.config.rules, &loaded.config.defines)
            .expect("predicate resolution failed");
    loaded.config.rules = resolved_rules;
    loaded
}

fn parse_facts(raw_facts: &[String]) -> may_i_core::ContextFacts {
    may_i::runtime_facts::parse_cli_facts(raw_facts).expect("failed to parse facts")
}

/// Render trace output for a command evaluation into a buffer.
fn render_output(command: &str, facts: &[String]) -> Vec<u8> {
    colored::control::set_override(true);

    let context = parse_facts(facts);
    let config = load_config();
    let (result, traces, colored_command, _audit) =
        evaluate_with_colorization(command, &config, &context).unwrap();
    let config_path = fixture_dir().join("config.lisp");

    let trust = InvocationTrust::with_loader(false, Box::new(|| None));
    let pipeline = CommandPipeline::with_trust(config, false, trust);
    let mut buf = Vec::new();
    EvalOutput {
        config_path: &config_path,
        trace_entries: &traces,
        command,
        colored_command: &colored_command,
        eval_result: &result,
    }
    .render(&mut buf, pipeline.terminal());
    buf
}

/// Normalise the config path line in output so it doesn't depend on the machine.
fn normalise_config_path(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for line in s.lines() {
        let stripped = output::strip_ansi(line);
        if stripped.trim_start().starts_with("config:") {
            // Replace the entire line with a normalised placeholder,
            // preserving any leading whitespace and ANSI codes up to "config:".
            result.push_str("  config: <config-path>");
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    // Preserve trailing content: if original doesn't end with newline, trim last
    if !s.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }
    result
}

#[test]
fn migrated_v1_stripped_snapshots() {
    let cases = load_cases();

    for case in &cases {
        let raw_output = render_output(&case.command, &case.facts);
        let output_str = String::from_utf8_lossy(&raw_output);
        let stripped = output::strip_ansi(&output_str);
        let normalised = normalise_config_path(&stripped);

        insta::assert_snapshot!(format!("{}_stripped", case.name), normalised);
    }
}

#[test]
fn migrated_v1_raw_snapshots() {
    let cases = load_cases();

    for case in &cases {
        let raw_output = render_output(&case.command, &case.facts);
        let output_str = String::from_utf8_lossy(&raw_output);
        let normalised = normalise_config_path(output_str.as_ref());

        insta::assert_snapshot!(format!("{}_raw", case.name), normalised);
    }
}

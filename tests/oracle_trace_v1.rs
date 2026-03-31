// Oracle trace snapshot tests for V1 config format.
//
// Each test case evaluates a command against the V1 fixture config and
// compares the rendered trace output against oracle snapshots captured
// from the previous release binary with COLUMNS=80 and CLICOLOR_FORCE=1.

use std::path::Path;

use serde::Deserialize;

use may_i::cmd_eval::{evaluate_segments, write_eval_output};
use may_i::output;

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

fn snapshot_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/oracle_v1")
        .leak()
}

fn load_cases() -> Vec<Case> {
    let content = std::fs::read_to_string(fixture_dir().join("cases.toml"))
        .expect("failed to read cases.toml");
    let cases: Cases = toml::from_str(&content).expect("failed to parse cases.toml");
    cases.case
}

fn load_config() -> may_i_core::ast::Config {
    let config_path = fixture_dir().join("config.lisp");
    let mut config = may_i_config::load(&config_path).expect("failed to load V1 fixture config");
    let (resolved_rules, _) =
        may_i_config::resolve::validate_and_resolve(&config.rules, &config.defines)
            .expect("predicate resolution failed");
    config.rules = resolved_rules;
    config
}

fn parse_facts(raw_facts: &[String]) -> may_i_core::ContextFacts {
    may_i::runtime_facts::parse_cli_facts(raw_facts).expect("failed to parse facts")
}

/// Render trace output for a command evaluation into a buffer.
fn render_output(command: &str, config: &may_i_core::ast::Config, facts: &[String]) -> Vec<u8> {
    colored::control::set_override(true);

    let term = output::Terminal::new(80);
    let context = parse_facts(facts);
    let (result, traces, colored_command) = evaluate_segments(command, config, &context);
    let display_path = output::shorten_home(&fixture_dir().join("config.lisp"));

    let mut buf = Vec::new();
    write_eval_output(
        &mut buf,
        &traces,
        command,
        &colored_command,
        &result,
        &display_path,
        &term,
    );
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

fn load_snapshot(name: &str, ext: &str) -> String {
    let path = snapshot_dir().join(format!("{name}.{ext}"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read snapshot {}: {e}", path.display()))
}

/// Produce a unified diff between expected and actual, for clear failure output.
fn unified_diff(expected: &str, actual: &str, label: &str) -> String {
    use similar::TextDiff;
    let diff = TextDiff::from_lines(expected, actual);
    let mut output = String::new();
    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            similar::ChangeTag::Delete => "-",
            similar::ChangeTag::Insert => "+",
            similar::ChangeTag::Equal => " ",
        };
        output.push_str(&format!("{sign}{change}"));
    }
    if output.lines().all(|l| l.starts_with(' ')) {
        String::new() // no diff
    } else {
        format!("=== {label} diff ===\n{output}")
    }
}

#[test]
fn oracle_v1_stripped_snapshots() {
    let cases = load_cases();
    let config = load_config();
    let mut failures = Vec::new();

    for case in &cases {
        let raw_output = render_output(&case.command, &config, &case.facts);
        let output_str = String::from_utf8_lossy(&raw_output);
        let stripped = output::strip_ansi(&output_str);
        let normalised_actual = normalise_config_path(&stripped);

        let expected = load_snapshot(&case.name, "txt");
        let normalised_expected = normalise_config_path(&expected);

        if normalised_actual != normalised_expected {
            let diff = unified_diff(&normalised_expected, &normalised_actual, &case.name);
            failures.push(format!("FAIL (stripped): {}\n{diff}", case.name));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} stripped snapshot(s) failed:\n\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }
}

#[test]
fn oracle_v1_raw_snapshots() {
    let cases = load_cases();
    let config = load_config();
    let mut failures = Vec::new();

    for case in &cases {
        let raw_output = render_output(&case.command, &config, &case.facts);
        let output_str = String::from_utf8_lossy(&raw_output);
        let normalised_actual = normalise_config_path(&output_str.as_ref());

        let expected = load_snapshot(&case.name, "raw");
        let normalised_expected = normalise_config_path(&expected);

        if normalised_actual != normalised_expected {
            // For raw comparison, strip ANSI from both sides for readable diff
            let diff = unified_diff(
                &output::strip_ansi(&normalised_expected),
                &output::strip_ansi(&normalised_actual),
                &format!("{} (raw, showing stripped for readability)", case.name),
            );
            failures.push(format!("FAIL (raw): {}\n{diff}", case.name));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{}/{} raw snapshot(s) failed:\n\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }
}

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
(rule (command "echo")
      (context (and (has :client/opencode)
                    (has [:opencode/agent "plan"])))
      (effect :allow "OpenCode plan agent"))
"#;

fn write_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(TEST_CONFIG.as_bytes())
        .expect("write temp config");
    f
}

fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path());
    cmd
}

fn trace_annotations(resp: &serde_json::Value) -> Vec<&serde_json::Value> {
    resp["trace"]
        .as_array()
        .expect("trace array")
        .iter()
        .flat_map(|entry| {
            entry["annotations"]
                .as_array()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn json_eval_matches_opencode_agent_context() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args([
            "--json",
            "eval",
            "--fact",
            ":client/opencode",
            "--fact",
            ":opencode/agent=plan",
            "echo hi",
        ])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["reason"], "OpenCode plan agent");

    let annotations = trace_annotations(&resp);
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_presence"
            && ann["key"] == ":client/opencode"
            && ann["matched"] == true
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_exact"
            && ann["key"] == ":opencode/agent"
            && ann["actual"] == "plan"
            && ann["matched"] == true
    }));
}

#[test]
fn json_eval_skips_different_opencode_agent() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args([
            "--json",
            "eval",
            "--fact",
            ":client/opencode",
            "--fact",
            ":opencode/agent=build",
            "echo hi",
        ])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "ask");

    let annotations = trace_annotations(&resp);
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_exact"
            && ann["key"] == ":opencode/agent"
            && ann["actual"] == "build"
            && ann["matched"] == false
    }));
}

#[test]
fn json_eval_omits_opencode_context_when_env_missing() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval", "echo hi"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "ask");

    let annotations = trace_annotations(&resp);
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_presence"
            && ann["key"] == ":client/opencode"
            && ann["matched"] == false
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_exact"
            && ann["key"] == ":opencode/agent"
            && ann["actual"].is_null()
            && ann["matched"] == false
            && ann["reason"] == "absent"
    }));
}

#[test]
fn json_eval_ignores_ambient_opencode_environment_without_fact_flags() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .env("MAYI_OPENCODE_AGENT", "plan")
        .env("OPENCODE", "1")
        .args(["--json", "eval", "echo hi"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "ask");

    let annotations = trace_annotations(&resp);
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_presence"
            && ann["key"] == ":client/opencode"
            && ann["matched"] == false
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_has_exact"
            && ann["key"] == ":opencode/agent"
            && ann["actual"].is_null()
            && ann["matched"] == false
            && ann["reason"] == "absent"
    }));
}

#[test]
fn eval_rejects_malformed_fact_flags() {
    let cfg = write_config();
    may_i(&cfg)
        .args(["eval", "--fact", "opencode/agent=plan", "echo hi"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "context fact key must be namespaced",
        ));
}

#[test]
fn plain_eval_trace_reflects_opencode_context() {
    let cfg = write_config();
    may_i(&cfg)
        .args([
            "eval",
            "--fact",
            ":client/opencode",
            "--fact",
            ":opencode/agent=plan",
            "echo hi",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(":client/opencode"))
        .stdout(predicate::str::contains(":opencode/agent"))
        .stdout(predicate::str::contains("OpenCode plan agent"));
}

#[test]
fn json_eval_includes_spans_array() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval", "echo hi"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert!(resp["spans"].is_array(), "spans field should be an array");
}

#[test]
fn json_eval_spans_have_expected_fields() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval", "ls"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    let spans = resp["spans"].as_array().expect("spans array");
    assert!(!spans.is_empty(), "should have at least one span");

    for span in spans {
        assert!(
            span["text"].is_string(),
            "each span should have a text field"
        );
        assert!(
            span["permission"].is_string(),
            "each span should have a permission field"
        );
        let perm = span["permission"].as_str().unwrap();
        assert!(
            ["allow", "ask", "deny", "ignore"].contains(&perm),
            "permission should be one of allow/ask/deny/ignore, got {}",
            perm
        );
    }
}

#[test]
fn json_eval_spans_with_operator_have_ignore_permission() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval", "true && ls"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    let spans = resp["spans"].as_array().expect("spans array");
    // Should have at least 3 spans: "true", " && ", "ls"
    assert!(
        spans.len() >= 3,
        "should have at least 3 spans for operator command"
    );

    // Find the operator span and verify it has "ignore" permission
    let operator_span = spans
        .iter()
        .find(|s| s["text"].as_str().is_some_and(|t| t.contains("&&")));
    assert!(
        operator_span.is_some(),
        "should have an operator span containing &&"
    );
    assert_eq!(
        operator_span.unwrap()["permission"],
        "ignore",
        "operator span should have ignore permission"
    );
}

#[test]
fn json_eval_spans_concatenate_to_original_command() {
    let cfg = write_config();
    let command = "  true && echo hello  ";
    let output = may_i(&cfg)
        .args(["--json", "eval", command])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    let spans = resp["spans"].as_array().expect("spans array");
    let reconstructed: String = spans
        .iter()
        .map(|s| s["text"].as_str().unwrap_or(""))
        .collect();

    assert_eq!(
        reconstructed, command,
        "concatenating span texts should reproduce original command exactly"
    );
}

#[test]
fn json_eval_complex_command_with_spans() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval", "ls && echo a || echo b"])
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert!(resp["spans"].is_array(), "spans field should be an array");
    let spans = resp["spans"].as_array().unwrap();
    assert!(
        spans.len() >= 5,
        "complex command should have multiple spans"
    );

    // Verify we have operator spans with ignore permission
    let operator_count = spans
        .iter()
        .filter(|s| {
            s["permission"] == "ignore"
                && (s["text"].as_str().unwrap_or("").contains("&&")
                    || s["text"].as_str().unwrap_or("").contains("||"))
        })
        .count();
    assert_eq!(
        operator_count, 2,
        "should have 2 operator spans with ignore permission"
    );
}

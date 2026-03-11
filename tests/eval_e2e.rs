use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
(rule (command "echo")
      (context (and (has :client/opencode)
                    (= :opencode/agent "plan")))
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
        ann["type"] == "context_has" && ann["key"] == ":client/opencode" && ann["matched"] == true
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_equals"
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
        ann["type"] == "context_equals"
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
        ann["type"] == "context_has" && ann["key"] == ":client/opencode" && ann["matched"] == false
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_equals"
            && ann["key"] == ":opencode/agent"
            && ann["actual"].is_null()
            && ann["matched"] == false
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
        ann["type"] == "context_has" && ann["key"] == ":client/opencode" && ann["matched"] == false
    }));
    assert!(annotations.iter().any(|ann| {
        ann["type"] == "context_equals"
            && ann["key"] == ":opencode/agent"
            && ann["actual"].is_null()
            && ann["matched"] == false
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

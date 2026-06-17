// Integration tests for recognising calls to script-local functions as
// internal calls (resolve to :allow, never `No rule for command …`).

mod common;

use common::{may_i, parse_json, write_config};

/// The motivating shape: a script defines functions and calls them, some
/// from inside another body. Only the dynamic `"$TGBIN"` command — out of
/// scope — should ask; every function call is internal.
#[test]
fn motivating_script_only_dynamic_command_asks() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
(rule "mkdir" (allow))
"#,
    );
    let script = r#"materialise() { mkdir -p "$BASE"; echo built; }
run_seeds() { echo seeding; }
deploy() { materialise "$BASE"; run_seeds; "$TGBIN" stack generate; }
materialise /tmp/x
run_seeds
deploy"#;

    let output = may_i(&cfg)
        .args(["--json", "eval", script])
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resp = parse_json(&output);

    // The residual ask is solely the dynamic `$TGBIN` command.
    assert_eq!(resp["decision"], "ask");
    assert_eq!(resp["reason"], "dynamic command name: $TGBIN");

    // Every function call rendered an intelligible internal-call trace line;
    // none reported a missing rule.
    let names: Vec<String> = resp["trace"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "local_function_call")
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"materialise".to_string()), "{names:?}");
    assert!(names.contains(&"run_seeds".to_string()), "{names:?}");
    assert!(names.contains(&"deploy".to_string()), "{names:?}");

    let reasons = serde_json::to_string(&resp["trace"]).unwrap();
    assert!(
        !reasons.contains("No rule for command `materialise`"),
        "internal calls must not report a missing rule: {reasons}"
    );
}

/// A call to a defined function does not ask even when nothing else gates it.
#[test]
fn lone_local_function_call_allows() {
    let cfg = write_config(r#"(rule "echo" (allow))"#);
    let output = may_i(&cfg)
        .args([
            "--json",
            "eval",
            "materialise() { echo hi; }; materialise foo",
        ])
        .output()
        .expect("run");
    assert!(output.status.success());
    let resp = parse_json(&output);
    assert_eq!(resp["decision"], "allow");
}

/// Shadowing a real command: the wrapper body is still authorised, so what
/// actually runs is gated, but the call itself is internal.
#[test]
fn defined_name_shadowing_external_is_internal() {
    let cfg = write_config(r#"(rule "echo" (allow))"#);
    // `git` is defined as a function; the call is internal and its body
    // (echo) is authorised. No `No rule for command `git`` despite no git rule.
    let output = may_i(&cfg)
        .args(["--json", "eval", "git() { echo wrapped; }; git push"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let resp = parse_json(&output);
    assert_eq!(resp["decision"], "allow");
    let reasons = serde_json::to_string(&resp["trace"]).unwrap();
    assert!(
        !reasons.contains("No rule for command `git`"),
        "shadowing call must be internal: {reasons}"
    );
}

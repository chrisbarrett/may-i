// Integration tests for eval with define predicates.

mod common;

use common::{may_i, write_config};

// ---------------------------------------------------------------------------
// 6.1 – End-to-end: eval with defines produces correct decision
// ---------------------------------------------------------------------------

#[test]
fn eval_define_matching_produces_correct_decision() {
    let cfg = write_config(
        r#"
(define is-safe (fact? :safe/context))
(rule "git" (when is-safe (effect :allow "git is safe")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "git commit", "--fact", ":safe/context"])
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["reason"], "git is safe");
}

#[test]
fn eval_define_not_matching_falls_through() {
    let cfg = write_config(
        r#"
(define is-safe (fact? :safe/context))
(rule "git" (when is-safe (effect :allow "git is safe")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "git commit"])
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(
        resp["decision"], "ask",
        "without the fact, define should not match and default to ask"
    );
}

#[test]
fn eval_define_equivalent_to_inline() {
    // Config with define
    let cfg_define = write_config(
        r#"
(define is-safe (fact? :safe/context))
(rule "git" (when is-safe (effect :deny "blocked")))
"#,
    );
    // Equivalent config with inline predicate
    let cfg_inline = write_config(
        r#"
(rule "git" (when (fact? :safe/context) (effect :deny "blocked")))
"#,
    );

    for fact_args in [vec!["--fact", ":safe/context"], vec![]] {
        let mut args_define = vec!["--json", "eval", "git push"];
        args_define.extend(&fact_args);
        let mut args_inline = vec!["--json", "eval", "git push"];
        args_inline.extend(&fact_args);

        let out_define = may_i(&cfg_define)
            .args(&args_define)
            .output()
            .expect("run define");
        let out_inline = may_i(&cfg_inline)
            .args(&args_inline)
            .output()
            .expect("run inline");

        let resp_define: serde_json::Value =
            serde_json::from_slice(&out_define.stdout).expect("JSON");
        let resp_inline: serde_json::Value =
            serde_json::from_slice(&out_inline.stdout).expect("JSON");

        assert_eq!(
            resp_define["decision"], resp_inline["decision"],
            "decision should match for facts {:?}",
            fact_args
        );
        assert_eq!(
            resp_define["reason"], resp_inline["reason"],
            "reason should match for facts {:?}",
            fact_args
        );
    }
}

#[test]
fn eval_transitive_define_resolves() {
    let cfg = write_config(
        r#"
(define base-check (fact? :trusted))
(define combined base-check)
(rule "git" (when combined (effect :allow "transitive match")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "git commit", "--fact", ":trusted"])
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["reason"], "transitive match");
}

// ---------------------------------------------------------------------------
// 6.2 – End-to-end: JSON trace contains var_ref annotations
// ---------------------------------------------------------------------------

#[test]
fn eval_json_trace_contains_var_ref_annotation() {
    let cfg = write_config(
        r#"
(define is-safe (fact? :safe/context))
(rule "git" (when is-safe (effect :allow "git is safe")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "git commit", "--fact", ":safe/context"])
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    let trace = &resp["trace"];
    assert!(trace.is_array(), "trace should be an array");

    let rules = trace.as_array().unwrap();
    assert!(!rules.is_empty(), "trace should have at least one rule");

    // Find a var_ref annotation in the trace
    let var_ref = find_annotation(rules, "var_ref");
    assert!(
        var_ref.is_some(),
        "trace should contain a var_ref annotation, got: {}",
        serde_json::to_string_pretty(&trace).unwrap()
    );

    let var_ref = var_ref.unwrap();
    assert_eq!(var_ref["name"], "is-safe");
    assert_eq!(var_ref["matched"], true);

    // var_ref should contain a body array with child annotations
    let body = &var_ref["body"];
    assert!(
        body.is_array(),
        "var_ref should have a body array, got: {}",
        serde_json::to_string_pretty(&var_ref).unwrap()
    );
}

#[test]
fn eval_json_trace_var_ref_unmatched() {
    let cfg = write_config(
        r#"
(define is-safe (fact? :safe/context))
(rule "git" (when is-safe (effect :allow "git is safe")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "git commit"])
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    let trace = &resp["trace"];
    let rules = trace.as_array().unwrap();

    let var_ref = find_annotation(rules, "var_ref");
    assert!(
        var_ref.is_some(),
        "trace should contain a var_ref annotation"
    );

    let var_ref = var_ref.unwrap();
    assert_eq!(var_ref["name"], "is-safe");
    assert_eq!(var_ref["matched"], false);

    // Body should still be present even for unmatched
    assert!(var_ref["body"].is_array());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively search JSON trace for an annotation with the given type.
fn find_annotation(value: &[serde_json::Value], ann_type: &str) -> Option<serde_json::Value> {
    for item in value {
        if let Some(found) = find_annotation_in_value(item, ann_type) {
            return Some(found);
        }
    }
    None
}

fn find_annotation_in_value(
    value: &serde_json::Value,
    ann_type: &str,
) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("type").and_then(|t| t.as_str()) == Some(ann_type) {
                return Some(value.clone());
            }
            for v in map.values() {
                if let Some(found) = find_annotation_in_value(v, ann_type) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_annotation_in_value(item, ann_type) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

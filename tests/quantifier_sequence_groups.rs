// Integration tests for sequence-group quantifiers end to end:
// parse → positional match → decision. Exercises the motivating
// "leading element required" semantics of `(? "run" (? "fast"))`.

mod common;

use common::{may_i, parse_json, write_config};

/// A read-only gate where the optional `run [fast]` prefix may precede the
/// verb, but a bare `fast` (without its leading `run`) must not slip through.
const CONFIG: &str = r#"
(rule "tool"
  (cond ((positional (? "run" (? "fast")) "build") (allow "ok"))
        (else (ask "nope"))))
"#;

fn decision(cmd: &str) -> serde_json::Value {
    let cfg = write_config(CONFIG);
    let output = may_i(&cfg)
        .args(["--json", "eval", cmd])
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_json(&output)
}

#[test]
fn group_skipped_then_verb() {
    assert_eq!(decision("tool build")["decision"], "allow");
}

#[test]
fn group_partial_inner_then_verb() {
    assert_eq!(decision("tool run build")["decision"], "allow");
}

#[test]
fn group_full_inner_then_verb() {
    assert_eq!(decision("tool run fast build")["decision"], "allow");
}

#[test]
fn group_leading_element_required() {
    // `fast` without its leading `run`: the group cannot match `fast`, so the
    // read-only branch does not apply and the decision floors to ask.
    assert_eq!(decision("tool fast build")["decision"], "ask");
}

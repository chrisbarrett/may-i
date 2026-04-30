// Integration tests for `(args-style ...)` tokenisation profiles.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};
use may_i_engine::evaluate;

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn eval(config_text: &str, command: &str, argv: &[&str]) -> Decision {
    let config = parse_config(config_text).expect("parse config");
    let facts = ContextFacts::default();
    let res = evaluate(command, &args(argv), &config, &facts).expect("evaluate");
    res.decision
}

// 3.1: `find . -name foo` with `:single-dash-long` and `(rule "find" (anywhere "-n"))`
// should NOT match — the `-name` token is not split into `-n -a -m -e`.
#[test]
fn single_dash_long_does_not_split_into_dash_n() {
    let cfg = r#"
(args-style "find" :single-dash-long)
(rule "find" (anywhere "-n"))
"#;
    let decision = eval(cfg, "find", &[".", "-name", "foo"]);
    assert_eq!(
        decision,
        Decision::Ask,
        "expected no false match — `-name` should not split under :single-dash-long",
    );
}

// 3.2: `kubectl -n foo get pods` with `:gnu :flags-with-values ("-n")` and
// `(rule "kubectl" (positional "get" "pods"))` ⇒ allow.
#[test]
fn flags_with_values_groups_short_flag_value() {
    let cfg = r#"
(args-style "kubectl" :gnu :flags-with-values ("-n"))
(rule "kubectl" (and (positional "get" "pods") (effect :allow)))
"#;
    let decision = eval(cfg, "kubectl", &["-n", "foo", "get", "pods"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.3: `tar xvzf archive.tgz` with `:legacy-bundle` ⇒ first token recognised
// as flag bundle. After expansion only `archive.tgz` is positional.
#[test]
fn legacy_bundle_treats_first_cluster_as_flags() {
    let cfg = r#"
(args-style "tar" :legacy-bundle)
(rule "tar" (and (exact "archive.tgz") (effect :allow)))
"#;
    let decision = eval(cfg, "tar", &["xvzf", "archive.tgz"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.4: `dd if=foo of=bar bs=1M` with `:key-value` ⇒ all `key=value` tokens
// recognised as flag-equivalent so no positional args remain.
#[test]
fn key_value_treats_keyvalue_tokens_as_flags() {
    let cfg = r#"
(args-style "dd" :key-value)
(rule "dd" (and (exact) (effect :allow)))
"#;
    let decision = eval(cfg, "dd", &["if=foo", "of=bar", "bs=1M"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.5: regression baseline — without `args-style` the `:gnu` behaviour
// continues to apply byte-for-byte: `-rf` splits, `(anywhere "-r")` matches.
#[test]
fn gnu_default_still_splits_combined_short_flags() {
    let cfg = r#"
(rule "rm" (and (anywhere "-r") (effect :deny "recursive")))
"#;
    let decision = eval(cfg, "rm", &["-rf", "/tmp/junk"]);
    assert_eq!(decision, Decision::Deny);
}

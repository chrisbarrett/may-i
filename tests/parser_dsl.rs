// Failing integration tests for the (define-arg-style …) / (parser …) DSL
// (per-command-arg-style §5). These describe the end-to-end behaviour the
// new tokeniser MUST deliver. They are expected to FAIL until §6
// (tokeniser rewrite) lands.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};
use may_i_engine::evaluate;

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn eval(config_text: &str, command: &str, argv: &[&str]) -> Decision {
    let config = parse_config(config_text).expect("parse config");
    let facts = ContextFacts::default();
    evaluate(command, &args(argv), &config, &facts)
        .expect("evaluate")
        .decision
}

// 5.1: `find . -name foo` under (parser "find" (style single-dash-long))
// must not split `-name` into `-n -a -m -e`.
#[test]
fn parser_find_single_dash_long_no_false_fire() {
    let cfg = r#"
(parser "find" (style single-dash-long))
(rule "find" (and (anywhere "-n") (effect :deny "matched -n")))
(rule "find" (effect :allow))
"#;
    let decision = eval(cfg, "find", &[".", "-name", "foo"]);
    assert_eq!(
        decision,
        Decision::Allow,
        "`-name` must stay one token under :single-dash-long",
    );
}

// 5.2: `kubectl -n my-ns get pods` under (parser kubectl (style gnu)
// (parameter ["n" "namespace"])) — `-n my-ns` groups; positional stream
// is [get, pods].
#[test]
fn parser_kubectl_parameter_value_pair() {
    let cfg = r#"
(parser "kubectl" (style gnu) (parameter ["n" "namespace"]))
(rule "kubectl" (and (positional "get" "pods") (effect :allow)))
"#;
    let decision = eval(cfg, "kubectl", &["-n", "my-ns", "get", "pods"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.3: `tar xvzf archive.tgz` under (parser "tar" (style legacy-bundle))
// — first token is a flag bundle.
#[test]
fn parser_tar_legacy_bundle_first_token_is_flags() {
    let cfg = r#"
(parser "tar" (style legacy-bundle))
(rule "tar" (and (exact "archive.tgz") (effect :allow)))
"#;
    let decision = eval(cfg, "tar", &["xvzf", "archive.tgz"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.4: `dd if=foo of=bar bs=1M` under (parser "dd" (style key-value)
// (parameter "if") (parameter "of") (parameter "bs")) — all classified
// as parameter-value pairs, no positional residue.
#[test]
fn parser_dd_key_value_classifies_all_kvs() {
    let cfg = r#"
(parser "dd" (style key-value)
  (parameter "if")
  (parameter "of")
  (parameter "bs"))
(rule "dd" (and (exact) (effect :allow)))
"#;
    let decision = eval(cfg, "dd", &["if=foo", "of=bar", "bs=1M"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.5: `bash -c "echo hi"` under (parser "bash" (style gnu)
// (parameter "c" (may-i *))) — inner `echo hi` re-authorised by may-i;
// no rule for "bash" needed (the may-i recursion sources the decision).
#[test]
fn parser_bash_may_i_recurses() {
    let cfg = r#"
(parser "bash" (style gnu) (parameter "c" (may-i *)))
(rule "echo" (effect :allow "safe"))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.6: (define-arg-style java (:overrides gnu :separators (" " "=" ":")))
// — `java -Xmx:512m App` parses `512m` as the parameter value.
#[test]
fn parser_java_overrides_separators() {
    let cfg = r#"
(define-arg-style java (:overrides gnu :separators (" " "=" ":")))
(parser "java" (style java) (parameter "Xmx"))
(rule "java" (and (positional "App") (effect :allow)))
"#;
    let decision = eval(cfg, "java", &["-Xmx:512m", "App"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.7: :pun :allow — bare `--enable` matches (flag "enable") but not
// (parameter "enable" *).
#[test]
fn parser_pun_allow_bare_param_matches_flag() {
    let cfg = r#"
(parser "tool" (style gnu) (parameter "enable"))
(rule "tool" (and (flag "enable") (effect :allow)))
"#;
    let decision = eval(cfg, "tool", &["--enable"]);
    assert_eq!(decision, Decision::Allow);
}

// 5.8: :pun :error — bare `if` (no `=`) under :key-value style fails
// with a tokenisation error. We surface this as a non-Allow decision
// (Ask = fall-through) at minimum; ideally the engine would propagate
// a parse error, but the binary contract is "do not allow".
#[test]
fn parser_pun_error_bare_param_does_not_allow() {
    let cfg = r#"
(parser "dd" (style key-value) (parameter "if"))
(rule "dd" (effect :allow))
"#;
    let decision = eval(cfg, "dd", &["if", "foo"]);
    assert_ne!(
        decision,
        Decision::Allow,
        "bare `if` under :pun :error must not allow",
    );
}

// 5.9: regression — command without (parser …) ⇒ gnu style applies
// byte-for-byte.
#[test]
fn parser_default_fallback_is_gnu() {
    let cfg = r#"
(rule "rm" (and (anywhere "-r") (effect :deny "recursive")))
"#;
    let decision = eval(cfg, "rm", &["-rf", "/tmp/junk"]);
    assert_eq!(decision, Decision::Deny);
}

// Integration tests for `(flag …)` and `(parameter …)` patterns.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};
use may_i_engine::evaluate;
use proptest::prelude::*;

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn eval(config_text: &str, command: &str, argv: &[&str]) -> Decision {
    let config = parse_config(config_text).expect("parse config");
    let facts = ContextFacts::default();
    let res = evaluate(command, &args(argv), &config, &facts).expect("evaluate");
    res.decision
}

// 3.1: `(rule "bash" (parameter "c" (authorise)))` evaluates `bash -c "echo hi"`
// correctly — recurses into the inner `echo hi` command.
#[test]
fn parameter_with_may_i_recurses_into_value() {
    let cfg = r#"
(rule "echo" (allow "echo always allowed"))
(rule "bash" (parameter "c" (authorise)))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi"]);
    assert_eq!(decision, Decision::Allow, "bash -c should recurse to echo");
}

// 3.2a: `(rule "rm" (not (flag "r")))` allows `rm file`.
#[test]
fn not_flag_allows_when_flag_absent() {
    let cfg = r#"
(rule "rm" (and (not (flag "r")) (allow "no -r")))
"#;
    let decision = eval(cfg, "rm", &["file"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.2b: `(rule "rm" (not (flag "r")))` rejects `rm -r dir`.
#[test]
fn not_flag_rejects_when_flag_present() {
    let cfg = r#"
(rule "rm" (and (not (flag "r")) (allow "no -r")))
"#;
    let decision = eval(cfg, "rm", &["-r", "dir"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.3: combined-shorts cluster — `rm -rf dir` should make `(flag "r")` match.
#[test]
fn flag_matches_inside_combined_short_cluster() {
    let cfg = r#"
(rule "rm" (and (not (flag "r")) (allow "no -r")))
"#;
    let decision = eval(cfg, "rm", &["-rf", "dir"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.4a: `(flag ["f" "force"])` matches `git push -f`.
#[test]
fn flag_vector_matches_short_form() {
    let cfg = r#"
(rule "git" (and (positional "push") (not (flag ["f" "force"])) (allow)))
"#;
    let decision = eval(cfg, "git", &["push", "-f"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.4b: `(flag ["f" "force"])` matches `git push --force`.
#[test]
fn flag_vector_matches_long_form() {
    let cfg = r#"
(rule "git" (and (positional "push") (not (flag ["f" "force"])) (allow)))
"#;
    let decision = eval(cfg, "git", &["push", "--force"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.5a: `(parameter ["X" "request"] "POST")` matches `curl -X POST`.
#[test]
fn parameter_matches_short_value() {
    let cfg = r#"
(rule "curl" (and (parameter ["X" "request"] "POST") (allow)))
"#;
    let decision = eval(cfg, "curl", &["-X", "POST", "https://example.com"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.5b: `(parameter ["X" "request"] "POST")` matches `curl --request=POST`.
#[test]
fn parameter_matches_long_equals_value() {
    let cfg = r#"
(rule "curl" (and (parameter ["X" "request"] "POST") (allow)))
"#;
    let decision = eval(cfg, "curl", &["--request=POST", "https://example.com"]);
    assert_eq!(decision, Decision::Allow);
}

// 3.5c: `(parameter ["X" "request"] "POST")` does not match a different value.
#[test]
fn parameter_does_not_match_different_value() {
    let cfg = r#"
(rule "curl" (and (parameter ["X" "request"] "POST") (allow)))
"#;
    let decision = eval(cfg, "curl", &["-X", "GET"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.5d: absent flag yields no match.
#[test]
fn parameter_absent_flag_does_not_match() {
    let cfg = r#"
(rule "curl" (and (parameter ["X" "request"] "POST") (allow)))
"#;
    let decision = eval(cfg, "curl", &["https://example.com"]);
    assert_eq!(decision, Decision::Ask);
}

// 3.6: `(parameter "c" FORM)` consumes the flag/value pair so a sibling
// `(positional …)` matcher sees the remaining args correctly.
//
// `kubectl -n my-ns get pods` ⇒ `(positional "get" "pods")` should still
// match because `-n my-ns` is consumed.
#[test]
fn parameter_consumes_flag_and_value_for_sibling_positional() {
    let cfg = r#"
(rule "kubectl"
  (and (parameter ["n" "namespace"] (regex ".*"))
       (positional "get" "pods")
       (allow)))
"#;
    let decision = eval(cfg, "kubectl", &["-n", "my-ns", "get", "pods"]);
    assert_eq!(decision, Decision::Allow);
}

// --- Properties ----------------------------------------------------------

/// Build an args list where some positions hold the named flag token and
/// others hold opaque positional fillers. Returns (args, flag_was_emitted).
fn build_args(name: &str, sprinkle: &[bool]) -> (Vec<String>, bool) {
    let token = if name.chars().count() == 1 {
        format!("-{name}")
    } else {
        format!("--{name}")
    };
    let mut args = Vec::with_capacity(sprinkle.len());
    let mut any = false;
    for &emit in sprinkle {
        if emit {
            args.push(token.clone());
            any = true;
        } else {
            args.push("filler".to_string());
        }
    }
    (args, any)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, max_shrink_iters: 50, ..ProptestConfig::default() })]

    /// 8.1 — `(flag X)` matches iff at least one tokenised flag has that name.
    /// We construct args with controlled flag presence and verify the match
    /// outcome lines up.
    #[test]
    fn property_flag_match_iff_present(
        sprinkle in proptest::collection::vec(any::<bool>(), 0..6),
        is_long in any::<bool>(),
    ) {
        let name = if is_long { "longflag" } else { "x" };
        let (args, expected_present) = build_args(name, &sprinkle);
        let cfg = format!(
            r#"(rule "tool" (and (flag "{name}") (allow)))"#
        );
        let config = parse_config(&cfg).unwrap();
        let facts = ContextFacts::default();
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let res = evaluate("tool", &argv_owned, &config, &facts).unwrap();
        if expected_present {
            prop_assert_eq!(res.decision, Decision::Allow);
        } else {
            prop_assert_eq!(res.decision, Decision::Ask);
        }
    }

    /// 8.2 — `(parameter X *)` matches iff `(flag X)` matches AND the flag has
    /// a following value. We compare the two patterns against the same input.
    /// The presence-only case is when the flag is followed by some positional
    /// (which becomes the value under implicit value-bearing registration).
    #[test]
    fn property_parameter_wildcard_matches_when_flag_has_value(
        is_long in any::<bool>(),
    ) {
        let name = if is_long { "longflag" } else { "x" };
        let token = if is_long {
            format!("--{name}")
        } else {
            format!("-{name}")
        };
        let cases: Vec<Vec<String>> = vec![
            vec![],                                 // absent
            vec![token.clone(), "VAL".into()],      // present with value
            vec![format!("{token}=VAL")],           // present with =-value
        ];
        for argv in cases {
            let cfg_flag = format!(
                r#"(rule "tool" (and (flag "{name}") (allow)))"#
            );
            let cfg_param = format!(
                r#"(rule "tool" (and (parameter "{name}" *) (allow)))"#
            );
            let facts = ContextFacts::default();
            let cf = parse_config(&cfg_flag).unwrap();
            let cp = parse_config(&cfg_param).unwrap();
            let rf = evaluate("tool", &argv, &cf, &facts).unwrap();
            let rp = evaluate("tool", &argv, &cp, &facts).unwrap();
            // Property: parameter * matches IFF the flag matches AND a value
            // exists. For our cases, present-with-value and present-with-=
            // both have a value; absent has neither.
            prop_assert_eq!(rf.decision, rp.decision, "argv={:?}", argv);
        }
    }

    /// 8.3 — `(not (flag X))` and `(flag X)` are duals: in any input, exactly
    /// one of the two rules applies.
    #[test]
    fn property_flag_and_not_flag_are_dual(
        sprinkle in proptest::collection::vec(any::<bool>(), 0..6),
    ) {
        let cfg_pos = r#"(rule "tool" (and (flag "x") (allow)))"#;
        let cfg_neg = r#"(rule "tool" (and (not (flag "x")) (allow)))"#;
        let (args, _) = build_args("x", &sprinkle);
        let facts = ContextFacts::default();
        let cp = parse_config(cfg_pos).unwrap();
        let cn = parse_config(cfg_neg).unwrap();
        let rp = evaluate("tool", &args, &cp, &facts).unwrap();
        let rn = evaluate("tool", &args, &cn, &facts).unwrap();
        let pos_matched = rp.decision == Decision::Allow;
        let neg_matched = rn.decision == Decision::Allow;
        prop_assert!(pos_matched ^ neg_matched, "args={:?}", args);
    }
}

// 3.7: `(flag "v")` is non-consuming — sibling matchers see the full stream.
//
// Without consumption, `(positional "show" "log")` should still match against
// `git -v show log` because `-v` was not value-bearing and `(flag …)` is a
// query.
#[test]
fn flag_does_not_consume_tokens() {
    let cfg = r#"
(rule "git"
  (and (flag "v")
       (positional "show" "log")
       (allow)))
"#;
    let decision = eval(cfg, "git", &["-v", "show", "log"]);
    assert_eq!(decision, Decision::Allow);
}

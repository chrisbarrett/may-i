// Integration tests for wrapper-tail matcher scoping (§9). When a parser
// declares `(tail (after …))`, argv matchers (anywhere/forbidden/flag/
// parameter/positional) MUST NOT see tokens from the tail slice.

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

// 9.3: a sudo-style wrapper with `(tail (after :flags))` exposes only
// outer flags to `(anywhere …)`. The inner `rm` token lives in the tail
// and is invisible to the wrapper's matchers.
#[test]
fn anywhere_does_not_see_tail_tokens() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (and (anywhere "rm") (deny "no rm via sudo")))
(rule "sudo" (allow))
"#;
    let decision = eval(cfg, "sudo", &["rm", "/tmp/x"]);
    assert_eq!(
        decision,
        Decision::Allow,
        "tail-slice token must not be visible to outer (anywhere …)"
    );
}

// `(forbidden …)` likewise scopes to outer; a forbidden token in the
// tail does not block the wrapper rule.
#[test]
fn forbidden_does_not_see_tail_tokens() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (and (forbidden "rm") (allow)))
"#;
    let decision = eval(cfg, "sudo", &["-u", "root", "rm", "/tmp/x"]);
    assert_eq!(
        decision,
        Decision::Allow,
        "(forbidden) must scope to outer when parser declares a tail"
    );
}

// `(flag …)` matchers see only outer flags. A flag-shaped token in the
// tail does not satisfy `(flag …)` against the wrapper.
#[test]
fn flag_matcher_scoped_to_outer() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (and (flag "r") (deny "no -r in sudo flags")))
(rule "sudo" (allow))
"#;
    // -r appears in the tail (it belongs to inner `rm`), not outer.
    let decision = eval(cfg, "sudo", &["rm", "-r", "/tmp/x"]);
    assert_eq!(decision, Decision::Allow);
}

// `(positional …)` matchers see only outer positionals. With AfterFlags
// the outer slice has no positionals — so a `(positional "rm")` matcher
// must not fire when the inner command is in the tail.
#[test]
fn positional_matcher_scoped_to_outer() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (and (positional "rm") (deny "no rm")))
(rule "sudo" (allow))
"#;
    let decision = eval(cfg, "sudo", &["rm", "/tmp/x"]);
    assert_eq!(decision, Decision::Allow);
}

// Sanity: outer flags and positionals are still visible to matchers.
#[test]
fn outer_flags_remain_visible() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (and (flag "u") (deny "no -u")))
(rule "sudo" (allow))
"#;
    let decision = eval(cfg, "sudo", &["-u", "root", "rm", "/tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

// End-to-end: the original sudo silent-bypass scenario now blocks.
#[test]
fn sudo_rm_rf_recurses_through_tail_authorise() {
    let cfg = r#"
(parser "sudo" (style gnu) (tail (after :flags)))
(rule "sudo" (tail (authorise)))
(rule "rm" (and (anywhere "-r") (deny "recursive rm denied")))
(rule "rm" (allow))
"#;
    let decision = eval(cfg, "sudo", &["rm", "-rf", "/tmp/x"]);
    assert_eq!(
        decision,
        Decision::Deny,
        "sudo rm -rf must delegate to inner rm rules and deny"
    );
}

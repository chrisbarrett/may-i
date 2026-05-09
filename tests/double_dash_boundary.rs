// Integration tests for `--` flag-stop honouring in `(anywhere …)` and
// `(forbidden …)` matchers (Lever A of the dsl-coherence change).

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

// 10.3: `git diff -- --foo` MUST NOT match `(anywhere "--foo")` because
// the post-`--` token is a path, not a flag.
#[test]
fn anywhere_skips_post_double_dash_token() {
    let cfg = r#"
(rule "git" (and (anywhere "--foo") (deny)))
(rule "git" (allow))
"#;
    let decision = eval(cfg, "git", &["diff", "--", "--foo"]);
    assert_eq!(
        decision,
        Decision::Allow,
        "(anywhere \"--foo\") must not match a post-`--` path token"
    );
}

// 10.4: `(forbidden "--foo")` MUST succeed (rule fires) when the
// `--foo`-shaped token only appears after `--`.
#[test]
fn forbidden_succeeds_when_target_is_post_double_dash() {
    let cfg = r#"
(rule "git" (and (forbidden "--foo") (allow)))
"#;
    let decision = eval(cfg, "git", &["diff", "--", "--foo"]);
    assert_eq!(
        decision,
        Decision::Allow,
        "(forbidden \"--foo\") must treat post-`--` tokens as paths"
    );
}

// Anywhere still matches pre-`--` tokens.
#[test]
fn anywhere_still_matches_pre_double_dash() {
    let cfg = r#"
(rule "git" (and (anywhere "--foo") (deny)))
(rule "git" (allow))
"#;
    let decision = eval(cfg, "git", &["diff", "--foo", "--", "path"]);
    assert_eq!(decision, Decision::Deny);
}

// Forbidden still fires when the target appears pre-`--`.
#[test]
fn forbidden_still_blocks_pre_double_dash_match() {
    let cfg = r#"
(rule "git" (and (forbidden "--foo") (allow)))
"#;
    let decision = eval(cfg, "git", &["diff", "--foo", "--", "path"]);
    // `(forbidden "--foo")` does NOT match (returns false), so the
    // surrounding rule short-circuits to no decision — which falls
    // through to `:ask`.
    assert_eq!(decision, Decision::Ask);
}

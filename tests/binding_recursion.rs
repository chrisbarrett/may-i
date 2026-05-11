//! Integration tests for §13.3 / §13.4: rule-body `(authorise #var)`
//! recursion through the binding environment that `parse_argv` produces.

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

// ── §13.3: per-wrapper recursion through (rest #cmd) ────────────────

#[test]
fn sudo_authorise_cmd_recurses_through_rest_binding() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (and (anywhere "-r") (deny "recursive rm denied")))
(rule "rm" (allow))
"#;
    let decision = eval(cfg, "sudo", &["rm", "-rf", "/tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn sudo_authorise_cmd_unbound_when_no_tail_no_match() {
    // `sudo` with no inner command — the prelude's `(flags posix)
    // (rest #cmd)` produces no rest tokens, so `(authorise #cmd)`
    // is no-match and falls through to the default Ask.
    let cfg = r#"(rule "sudo" (authorise #cmd))"#;
    let decision = eval(cfg, "sudo", &[]);
    assert_eq!(decision, Decision::Ask);
}

#[test]
fn nix_until_command_recurses_only_on_post_boundary_tokens() {
    // Prelude declares `(flags (until "--command" "-c")) (rest #cmd)`.
    let cfg = r#"
(rule "nix" (authorise #cmd))
(rule "echo" (deny "echo banned"))
"#;
    let decision = eval(
        cfg,
        "nix",
        &["shell", "nixpkgs#hello", "--command", "echo", "hi"],
    );
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn nix_until_command_boundary_absent_no_match() {
    let cfg = r#"
(rule "nix" (authorise #cmd))
"#;
    let decision = eval(cfg, "nix", &["shell", "nixpkgs#hello"]);
    assert_eq!(decision, Decision::Ask);
}

// ── §13.3: parameter-bound recursion ────────────────────────────────

#[test]
fn bash_c_recurses_through_parameter_binding() {
    // Prelude bash parser: `(parameter "c" #cmd)`. `bash -c "echo hi"`
    // recurses on the captured value.
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo" (allow))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi"]);
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn nix_shell_run_recurses_through_parameter_binding() {
    let cfg = r#"
(rule "nix-shell" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "nix-shell", &["--run", "rm /tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

// ── §13.3: positional binding + (matches? #var …) ───────────────────

#[test]
fn ssh_host_binding_drives_rule_branch() {
    // Prelude ssh: `(positional #host (regex "^[^-].*")) (rest #cmd)`.
    let cfg = r#"
(rule "ssh"
  (when (matches? #host (regex "^prod-")) (deny "no prod ssh")))
(rule "ssh" (authorise #cmd))
(rule "ls" (allow))
"#;
    assert_eq!(
        eval(cfg, "ssh", &["prod-1", "ls"]),
        Decision::Deny,
        "prod host must trigger deny"
    );
    assert_eq!(
        eval(cfg, "ssh", &["staging-1", "ls"]),
        Decision::Allow,
        "non-prod host must recurse and allow"
    );
}

#[test]
fn bound_predicate_distinguishes_optional_capture() {
    // bash with no -c flag: `#cmd` is Unbound; the matcher must
    // recognise that.
    let cfg = r#"
(rule "bash"
  (cond
    ((bound? #cmd) (deny "no bash -c"))
    (else (allow))))
"#;
    assert_eq!(
        eval(cfg, "bash", &["-c", "echo"]),
        Decision::Deny,
        "bound #cmd ⇒ deny branch"
    );
    assert_eq!(
        eval(cfg, "bash", &[]),
        Decision::Allow,
        "unbound #cmd ⇒ else branch"
    );
}

// ── §13.4: chained wrappers — three-layer recursion ─────────────────

#[test]
fn chained_wrappers_recurse_through_three_layers() {
    // `mise exec -- timeout 30 cargo test`
    //   → mise's (flags (until "--")) binds #cmd = [timeout, 30, cargo, test]
    //   → authorise #cmd ⇒ recurse on `timeout 30 cargo test`
    //   → timeout's (positional #duration …) (rest #cmd) binds #cmd = [cargo, test]
    //   → authorise #cmd ⇒ recurse on `cargo test`
    //   → cargo rule fires.
    let cfg = r#"
(rule "mise" (authorise #cmd))
(rule "timeout" (authorise #cmd))
(rule "cargo" (deny "no cargo"))
"#;
    let decision = eval(
        cfg,
        "mise",
        &["exec", "--", "timeout", "30", "cargo", "test"],
    );
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn chained_wrappers_set_nested_via_facts() {
    // The :via fact accumulates through the chain. The innermost
    // rule can see (fact? [:via "mise"]) AND (fact? [:via "timeout"]).
    let cfg = r#"
(rule "mise" (authorise #cmd))
(rule "timeout" (authorise #cmd))
(rule "cargo"
  (when (and (fact? [:via "mise"]) (fact? [:via "timeout"]))
    (deny "deeply wrapped cargo denied")))
"#;
    let decision = eval(
        cfg,
        "mise",
        &["exec", "--", "timeout", "30", "cargo", "test"],
    );
    assert_eq!(decision, Decision::Deny);
}

// ── Compound inner: recursion must decompose into EvalUnits ─────────

#[test]
fn authorise_recurses_into_and_compound_inner() {
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo" (allow))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi && rm -rf /"]);
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn authorise_recurses_into_pipe_compound_inner() {
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo" (allow))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi | rm -rf /"]);
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn authorise_recurses_into_if_then_fi_inner() {
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "bash", &["-c", "if true; then rm -rf /; fi"]);
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn authorise_simple_inner_still_works() {
    // Regression: a simple inner must continue to flow through the
    // shared recursive evaluator and produce the same result.
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo" (allow))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi"]);
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn authorise_compound_via_propagates_to_every_unit() {
    // Both inner units must see :via "bash" — exercises the per-unit
    // fact accumulation.
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo"
  (when (fact? [:via "bash"]) (allow "via bash")))
(rule "ls"
  (when (fact? [:via "bash"]) (allow "via bash")))
"#;
    let decision = eval(cfg, "bash", &["-c", "echo hi && ls /"]);
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn authorise_dynamic_inner_command_asks() {
    // The inner has a dynamic command name (`$X arg`). Decompose
    // emits an `EvalUnit::DynamicCommand`, which the shared helper
    // surfaces as Ask with a reason mentioning the dynamic name.
    let cfg = r#"
(rule "bash" (authorise #cmd))
"#;
    let config = parse_config(cfg).expect("parse config");
    let facts = ContextFacts::default();
    let result = evaluate("bash", &args(&["-c", "$X arg"]), &config, &facts).expect("evaluate");
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap_or_default();
    assert!(
        reason.contains("dynamic"),
        "reason should mention dynamic command name; got {reason}"
    );
}

#[test]
fn authorise_compound_strictest_wins_across_units() {
    // Two inner units, one Allow + one Deny — Deny wins (strictest).
    let cfg = r#"
(rule "bash" (authorise #cmd))
(rule "echo" (allow))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "bash", &["-c", "rm /tmp/x ; echo done"]);
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn authorise_through_rest_chains_into_parameter_compound() {
    // `(rest #cmd)` path on sudo. The inner is `sh -c "echo a"` — sh
    // has its own `(parameter "c" #cmd)` in the prelude, so this
    // stacks two recursions, the inner one a compound. We avoid
    // tokens that contain shell metacharacters inside the (rest)
    // binding — `(rest)` joins tokens with single spaces and loses
    // quote boundaries, so compound forms must enter via a parameter
    // capture (preserved as one string) rather than via (rest).
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "sh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "sudo", &["sh", "-c", "echo a && rm /tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

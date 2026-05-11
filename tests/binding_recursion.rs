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

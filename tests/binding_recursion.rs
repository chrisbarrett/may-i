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

// ── §13.4: chained carriers — three-layer recursion ─────────────────

#[test]
fn chained_carriers_recurse_through_three_layers() {
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
fn chained_carriers_set_nested_via_facts() {
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
    let reason = result.reason.as_deref().unwrap_or_default();
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
    // stacks two recursions, the inner one a compound. Token-list
    // recursion preserves the quoted third-arg as one token, which
    // sh then re-binds via its `(parameter "c" #cmd)` capture.
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "sh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "sudo", &["sh", "-c", "echo a && rm /tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

// ── Token-list quoting fix: §1.x in tasks.md ───────────────────────

/// §1.1 bypass reproducer. With token-list quoting preserved, sudo's
/// `#cmd` binds `[bash, -c, "echo a && rm -rf /tmp/x"]`; the third
/// token survives recursion as a single string and reaches bash's
/// `(parameter "c" #cmd)` intact. The inner `rm` rule fires inside
/// bash's frame — not as a sibling at sudo's frame.
#[test]
fn sudo_bash_c_token_list_preserves_quoted_third_token() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "bash" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "sudo", &["bash", "-c", "echo a && rm -rf /tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

/// §1.2 :via-gated deny survives wrapper chain. Under the old
/// join-and-parse, the `rm` unit emerged as a sibling at sudo's
/// frame, so `:via "bash"` was never set on the rm evaluation and
/// the predicate-gated deny silently vanished.
#[test]
fn sudo_bash_c_via_bash_fact_reaches_inner_rm() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "bash" (authorise #cmd))
(rule "rm" (when (fact? [:via "bash"]) (deny "rm via bash")))
"#;
    let config = parse_config(cfg).expect("parse config");
    let facts = ContextFacts::default();
    let result = evaluate(
        "sudo",
        &args(&["bash", "-c", "echo a && rm /tmp/x"]),
        &config,
        &facts,
    )
    .expect("evaluate");
    assert_eq!(result.decision, Decision::Deny);
    let reason = result.reason.as_deref().unwrap_or_default();
    assert!(reason.contains("rm via bash"), "got reason: {reason}");
}

/// §1.3 the `parser-bindings` spec scenario that was previously
/// unsatisfied: a compound `if … fi` body inside `sh -c` reached via
/// sudo's `(rest #cmd)` resolves to deny.
#[test]
fn sudo_sh_c_if_then_fi_resolves_to_deny() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "sh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "sudo", &["sh", "-c", "if true; then rm /; fi"]);
    assert_eq!(decision, Decision::Deny);
}

/// §1.4 ssh's `(rest #cmd)` binds a single quoted command; the
/// single-token list re-parses as a command line because there is no
/// outer-shell boundary to preserve.
#[test]
fn ssh_single_quoted_command_re_parses_as_command_line() {
    let cfg = r#"
(rule "ssh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "ssh", &["host", "ls && rm /tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

/// §1.5 regression: existing `sudo rm -rf /tmp/x` still denies (all
/// tokens metacharacter-free → token-list path agrees with the old
/// join-and-parse path).
#[test]
fn sudo_rm_rf_regression_still_denies() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (and (anywhere "-r") (deny "recursive rm denied")))
"#;
    let decision = eval(cfg, "sudo", &["rm", "-rf", "/tmp/x"]);
    assert_eq!(decision, Decision::Deny);
}

/// §1.6 token-list with a dynamic-shaped `tokens[0]`: the recursion
/// surfaces :ask with a reason that mentions the dynamic command
/// name. Driven via an `xargs`-shaped wrapper whose `(rest)` carries
/// the unresolved variable as argv[0].
#[test]
fn token_list_dynamic_first_token_asks_with_reason() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
"#;
    let config = parse_config(cfg).expect("parse config");
    let facts = ContextFacts::default();
    let result = evaluate("sudo", &args(&["$X", "arg"]), &config, &facts).expect("evaluate");
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("dynamic"),
        "reason should mention dynamic command name; got {reason}"
    );
}

/// §1.7 empty token-list (`(rest #cmd)` with no tail tokens) remains
/// a no-match. This case already passed pre-fix; verify still.
#[test]
fn token_list_empty_remains_no_match() {
    let cfg = r#"(rule "sudo" (authorise #cmd))"#;
    let decision = eval(cfg, "sudo", &[]);
    assert_eq!(decision, Decision::Ask);
}

// ── §5.2 Bypass equivalence proptest ────────────────────────────────

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 64,
        ..ProptestConfig::default()
    })]

    /// Bypass equivalence: for any well-formed inner command `c` whose
    /// tokens are metacharacter-free, evaluating `bash -c c` directly
    /// SHALL produce the same decision as evaluating
    /// `sudo bash -c c` under the wrapper rule set.
    ///
    /// Pre-fix, the wrapper chain joined sudo's `(rest)` tokens into
    /// `bash -c c1 c2 …` and re-parsed, exposing inner shell
    /// metacharacters as structure. Post-fix the inner argv reaches
    /// bash intact via token-list recursion.
    #[test]
    fn prop_sudo_bash_c_matches_direct_bash_c(
        inner in proptest::collection::vec("[a-zA-Z0-9_/-]{1,6}", 1..4),
    ) {
        let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "bash" (authorise #cmd))
(rule "rm" (deny "no rm"))
(rule "echo" (allow))
"#;
        let inner_cmd = inner.join(" ");
        let direct = eval(cfg, "bash", &["-c", inner_cmd.as_str()]);
        // sudo's `(rest)` carries the third token (the quoted inner
        // command line) as a single string; the token-list
        // recursion must preserve that boundary.
        let mut sudo_argv: Vec<&str> = vec!["bash", "-c"];
        sudo_argv.push(inner_cmd.as_str());
        let wrapped = eval(cfg, "sudo", &sudo_argv);
        prop_assert_eq!(direct, wrapped);
    }
}

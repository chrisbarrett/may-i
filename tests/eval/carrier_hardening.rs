//! Integration tests for the hardened prelude Carrier parsers: each
//! carrier must declare its value-taking option flags so the inner
//! command is identified correctly and carrier rules recurse into the
//! real target rather than a swallowed flag value.
//!
//! See `openspec/changes/harden-carrier-parsers`. `nice` is the
//! template: it already declares `-n`, so `nice -n 5 rm` recurses to
//! `rm`. Each test below mirrors that shape (design D3): bind
//! `(rule "<carrier>" (authorise #cmd))` + `(rule "rm" (deny …))` and
//! assert the inner command is `rm` (decision `:deny`), proving the
//! flag value was consumed as the flag's argument, not the command.

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

// ── 2.1 sudo ─────────────────────────────────────────────────────────

#[test]
fn sudo_user_flag_recurses_to_real_command() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    // Pre-hardening: `-u` was valueless, so `postgres` landed at
    // rest[0] and was mistaken for the inner command.
    assert_eq!(
        eval(cfg, "sudo", &["-u", "postgres", "rm", "-rf", "/tmp/x"]),
        Decision::Deny
    );
}

#[test]
fn sudo_multiple_value_flags_recurse_to_real_command() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(
            cfg,
            "sudo",
            &["-g", "wheel", "-p", "prompt", "rm", "-rf", "/tmp/x"]
        ),
        Decision::Deny
    );
}

#[test]
fn sudo_long_form_value_flag_recurses() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "sudo", &["--user=postgres", "rm", "-rf", "/tmp/x"]),
        Decision::Deny
    );
}

// ── 2.2 ssh ──────────────────────────────────────────────────────────

#[test]
fn ssh_value_flags_keep_host_and_recurse() {
    // `-i key -p 22` must be consumed as flag values so `host` binds
    // `#host` and `rm` is the inner command (not `22`).
    let cfg = r#"
(rule "ssh"
  (when (matches? #host (regex "^host$")) (authorise #cmd)))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(
            cfg,
            "ssh",
            &["-i", "key", "-p", "22", "host", "rm", "-rf", "/tmp"]
        ),
        Decision::Deny
    );
}

#[test]
fn ssh_o_option_recurses() {
    let cfg = r#"
(rule "ssh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(
            cfg,
            "ssh",
            &[
                "-o",
                "StrictHostKeyChecking=no",
                "host",
                "rm",
                "-rf",
                "/tmp"
            ]
        ),
        Decision::Deny
    );
}

// ── 2.3 env ──────────────────────────────────────────────────────────

#[test]
fn env_unset_short_recurses() {
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "env", &["-u", "SDKROOT", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

#[test]
fn env_unset_long_recurses() {
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "env", &["--unset=SDKROOT", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

#[test]
fn env_bsd_altpath_value_flag_recurses() {
    // BSD-only `-P altpath` is value-taking (macOS `man env`:
    // "Search the set of directories specified by altpath"); GNU env
    // has no `-P`, so declaring it never mis-parses on Linux. The
    // altpath value is consumed and `rm` is the inner command.
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "env", &["-P", "/usr/bin", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── 2.4 ionice ───────────────────────────────────────────────────────

#[test]
fn ionice_class_flags_recurse() {
    let cfg = r#"
(rule "ionice" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "ionice", &["-c", "2", "-n", "0", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── 2.5 chrt ─────────────────────────────────────────────────────────

#[test]
fn chrt_priority_positional_then_recurse() {
    // `-r` is a valueless policy flag; `10` is the required #priority
    // positional; `rm` is the inner command.
    let cfg = r#"
(rule "chrt"
  (when (matches? #priority (regex "^10$")) (authorise #cmd)))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "chrt", &["-r", "10", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

#[test]
fn chrt_value_flag_recurses() {
    let cfg = r#"
(rule "chrt" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    // -T sched-runtime takes a value; 10 is then #priority, rm the cmd.
    assert_eq!(
        eval(cfg, "chrt", &["-T", "5000", "10", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── 2.6 strace ───────────────────────────────────────────────────────

#[test]
fn strace_string_limit_recurses() {
    let cfg = r#"
(rule "strace" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "strace", &["-s", "256", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── 2.7 time ─────────────────────────────────────────────────────────

#[test]
fn time_output_flag_recurses() {
    let cfg = r#"
(rule "time" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "time", &["-o", "out.txt", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── 2.8 xargs ────────────────────────────────────────────────────────

#[test]
fn xargs_max_chars_recurses() {
    let cfg = r#"
(rule "xargs" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "xargs", &["-s", "1000", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

// ── Scenario 6: a declaration must not make a valueless/optional-arg
// flag consume the command operand (the inverse mis-parse). ──────────

#[test]
fn xargs_optional_eof_flag_does_not_swallow_command() {
    // GNU `-e[eof-str]` takes an *optional* argument, so `xargs -e rm`
    // treats `-e` as valueless and `rm` as the command. `-e`/`--eof`
    // must NOT be declared value-taking, else `rm` is swallowed.
    let cfg = r#"
(rule "xargs" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "xargs", &["-e", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
    // `-E eofstr` (mandatory on BSD and GNU) still consumes its value.
    assert_eq!(
        eval(cfg, "xargs", &["-E", "END", "rm", "-rf", "/tmp"]),
        Decision::Deny
    );
}

#[test]
fn sudo_overloaded_h_flag_does_not_swallow_command() {
    // `sudo -h` alone is help (valueless); declaring short `-h`
    // value-taking would make `sudo -h rm` swallow `rm`. The
    // unambiguous long `--host` remains value-taking.
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "sudo", &["-h", "rm", "-rf", "/tmp"]),
        Decision::Deny,
        "bare -h must be valueless so rm recurses"
    );
    assert_eq!(
        eval(cfg, "sudo", &["--host=remote", "rm", "-rf", "/tmp"]),
        Decision::Deny,
        "long --host still consumes its value"
    );
}

// ── 3.1 gotracksuit motivating shape ────────────────────────────────

#[test]
fn env_unset_with_assignment_then_path_command_resolves_inner() {
    // `env -u SDKROOT /usr/bin/xcrun swift test …` — with `-u` declared
    // value-taking, `SDKROOT` is consumed and the inner command is the
    // path form `/usr/bin/xcrun` (not a swallowed flag value or env var
    // name). The path form does not match `(rule "xcrun")` by basename
    // (out of scope per proposal), so we assert recursion *reaches* an
    // inner command by denying the path token directly.
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "/usr/bin/xcrun" (deny "no xcrun"))
"#;
    assert_eq!(
        eval(
            cfg,
            "env",
            &["-u", "SDKROOT", "/usr/bin/xcrun", "swift", "test"]
        ),
        Decision::Deny
    );
}

// ── 3.2 cross-platform short/long pairs ──────────────────────────────

#[test]
fn env_bsd_short_and_gnu_long_both_recurse() {
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "env", &["-u", "VAR", "rm", "/tmp"]),
        Decision::Deny,
        "BSD short -u"
    );
    assert_eq!(
        eval(cfg, "env", &["--unset", "VAR", "rm", "/tmp"]),
        Decision::Deny,
        "GNU long --unset (space separator)"
    );
    assert_eq!(
        eval(cfg, "env", &["--unset=VAR", "rm", "/tmp"]),
        Decision::Deny,
        "GNU long --unset (= separator)"
    );
}

#[test]
fn sudo_short_and_long_user_both_recurse() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "sudo", &["-u", "root", "rm", "/tmp"]),
        Decision::Deny,
        "short -u"
    );
    assert_eq!(
        eval(cfg, "sudo", &["--user", "root", "rm", "/tmp"]),
        Decision::Deny,
        "long --user (space)"
    );
    assert_eq!(
        eval(cfg, "sudo", &["--user=root", "rm", "/tmp"]),
        Decision::Deny,
        "long --user (=)"
    );
}

#[test]
fn xargs_max_chars_short_and_long_both_recurse() {
    let cfg = r#"
(rule "xargs" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "xargs", &["-s", "1000", "rm", "/tmp"]),
        Decision::Deny,
        "short -s"
    );
    assert_eq!(
        eval(cfg, "xargs", &["--max-chars=1000", "rm", "/tmp"]),
        Decision::Deny,
        "long --max-chars"
    );
}

// ── Adversarial review: value-flags consume their argument so the
// command recurses; edge cases are fail-safe (never silently Allow). ─

#[test]
fn xargs_arg_file_value_flag_recurses() {
    // GNU `-a/--arg-file` takes a file argument; `rm` is the command.
    let cfg = r#"
(rule "xargs" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "xargs", &["-a", "file.txt", "rm", "-rf", "/"]),
        Decision::Deny
    );
}

#[test]
fn time_format_value_flag_recurses() {
    // GNU `-f format` takes the format string; `rm` is the command.
    let cfg = r#"
(rule "time" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "time", &["-f", "%E", "rm", "-rf", "/"]),
        Decision::Deny
    );
}

#[test]
fn ionice_multiple_value_flags_recurse() {
    let cfg = r#"
(rule "ionice" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    assert_eq!(
        eval(cfg, "ionice", &["-c", "1", "-n", "7", "rm", "-rf", "/"]),
        Decision::Deny
    );
}

// `--` end-of-options is the engine's `(flags posix)` boundary, not
// part of this data-only change. These pin the current behaviour:
// after `--` the carrier's `(rest)`/positional binding does not
// resolve the inner command, so the decision floors to the safe `:ask`
// (NOT a silent allow — no bypass). If `--` handling is later improved
// to recurse, update these to `Deny` deliberately.

#[test]
fn sudo_double_dash_floors_to_ask_not_allow() {
    let cfg = r#"
(rule "sudo" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "sudo", &["-u", "postgres", "--", "rm", "-rf", "/"]);
    assert_eq!(decision, Decision::Ask);
    assert_ne!(decision, Decision::Allow, "must never silently allow rm");
}

#[test]
fn ssh_double_dash_floors_to_ask_not_allow() {
    let cfg = r#"
(rule "ssh" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "ssh", &["-p", "22", "--", "host", "rm", "-rf", "/"]);
    assert_eq!(decision, Decision::Ask);
    assert_ne!(decision, Decision::Allow, "must never silently allow rm");
}

#[test]
fn env_double_dash_floors_to_ask_not_allow() {
    let cfg = r#"
(rule "env" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "env", &["-u", "VAR", "--", "rm", "-rf", "/"]);
    assert_eq!(decision, Decision::Ask);
    assert_ne!(decision, Decision::Allow, "must never silently allow rm");
}

#[test]
fn chrt_negative_priority_floors_to_ask_not_allow() {
    // `-1` matches neither a declared flag nor the `^[0-9]+$` priority
    // positional, so `#priority` is unbound and recursion no-matches →
    // fail-safe `:ask`, never a silent allow.
    let cfg = r#"
(rule "chrt" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "chrt", &["-r", "-1", "rm", "-rf", "/"]);
    assert_eq!(decision, Decision::Ask);
    assert_ne!(decision, Decision::Allow, "must never silently allow rm");
}

#[test]
fn chrt_double_dash_floors_to_ask_not_allow() {
    let cfg = r#"
(rule "chrt" (authorise #cmd))
(rule "rm" (deny "no rm"))
"#;
    let decision = eval(cfg, "chrt", &["--", "10", "rm", "-rf", "/"]);
    assert_eq!(decision, Decision::Ask);
    assert_ne!(decision, Decision::Allow, "must never silently allow rm");
}

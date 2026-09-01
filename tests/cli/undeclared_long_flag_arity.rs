// Regression coverage for the undeclared-long-flag value-shape guard.
//
// Reproductions from the change `refine-undeclared-long-flag-arity`,
// expressed as embedded `(check …)` forms so they run under `may-i check`.
// All configs use the default gnu style with no cargo parser unless a test
// explicitly declares one. The `may_i` helper isolates the child's cwd to a
// temp dir and neutralises config discovery, so repo-local `.may-i.lisp`
// files never leak into these checks.

use crate::common::{may_i, parse_json, write_config};

// Repro #1 — value-shape guard: `--quiet` no longer eats the flag-shaped
// `--bin`, so the `run … -- … eval` adjacency survives and
// `(positional "run" "--")` matches → allow.
#[test]
fn flag_then_flag_keeps_positional_adjacency() {
    let cfg = write_config(
        r#"(rule "cargo"
  (when (positional "run" "--") (allow "cargo run wrapper"))
  (check :allow "cargo run --quiet --bin may-i -- eval"))"#,
    );
    let output = may_i(&cfg).args(["check", "--json"]).output().expect("run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resp = parse_json(&output);
    assert_eq!(resp["passed"], 1, "the flag-then-flag repro should allow");
    assert_eq!(resp["failed"], 0);
}

// Repro #2 — documented limitation: a boolean flag immediately before a bare
// subcommand cannot be told apart by shape from a value flag, so `--release`
// still consumes `build`; `(positional "build")` does not match → ask.
#[test]
fn flag_then_bare_subcommand_still_consumes_under_default_gnu() {
    let cfg = write_config(
        r#"(rule "cargo"
  (when (positional "build") (allow "cargo build"))
  (check :ask "cargo --release build"))"#,
    );
    let output = may_i(&cfg).args(["check", "--json"]).output().expect("run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resp = parse_json(&output);
    assert_eq!(
        resp["passed"], 1,
        "under default gnu, `--release` consumes `build` → ask (limitation)"
    );
}

// Repro #2, mitigated — declaring `(flag "release")` on the parser fixes the
// flag's arity to value-less, so `build` stays in the residual and
// `(positional "build")` matches → allow.
#[test]
fn declaring_the_flag_keeps_the_subcommand_visible() {
    let cfg = write_config(
        r#"(parser "cargo" (style gnu) (flag "release"))
(rule "cargo"
  (when (positional "build") (allow "cargo build"))
  (check :allow "cargo --release build"))"#,
    );
    let output = may_i(&cfg).args(["check", "--json"]).output().expect("run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resp = parse_json(&output);
    assert_eq!(
        resp["passed"], 1,
        "declaring (flag \"release\") keeps `build` in the residual → allow"
    );
}

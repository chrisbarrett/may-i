// Integration tests for the `fmt` subcommand.

use crate::common::{may_i, may_i_cmd, write_config};
use predicates::prelude::*;
use tempfile::NamedTempFile;

fn read_file(f: &NamedTempFile) -> String {
    std::fs::read_to_string(f.path()).expect("read")
}

#[test]
fn fmt_round_trips_audit_form_with_sorted_subforms() {
    let cfg = write_config("(audit (threshold :ask) (file \"x.jsonl\"))\n");
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .success();

    let out = read_file(&cfg);
    let file_pos = out.find(r#"(file "x.jsonl")"#).expect(&out);
    let threshold_pos = out.find("(threshold :ask)").expect(&out);
    assert!(file_pos < threshold_pos, "subforms not sorted: {out}");

    // Idempotent: a second fmt --check is a clean no-op.
    may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .success();
}

/// Task 6.1: a config containing a sequence-group quantifier formats stably
/// across two passes (the second `fmt --check` is a clean no-op).
#[test]
fn fmt_is_idempotent_on_sequence_group() {
    let cfg = write_config("(rule \"tool\" (positional (? \"run\" (? \"--\")) (* *)))\n");
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .success();

    let after_first = read_file(&cfg);
    assert!(
        after_first.contains(r#"(? "run" (? "--"))"#),
        "group form not preserved: {after_first}"
    );

    // Second pass must be a no-op.
    may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .success();
    assert_eq!(after_first, read_file(&cfg), "fmt is not idempotent");
}

#[test]
fn fmt_single_file_rewrites_in_place() {
    // Parser body order is canonicalised:
    //   style → flags → flag → parameter → positional → rest
    // The source declares them out of order; fmt reorders.
    let cfg = write_config(
        r#"(parser "git" (parameter "C") (rest #cmd) (flag "v") (style gnu) (flags posix))
"#,
    );
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .success();

    let out = read_file(&cfg);
    let style_pos = out.find("(style gnu)").expect(&out);
    let flags_pos = out.find("(flags posix)").expect(&out);
    let flag_pos = out.find(r#"(flag "v")"#).expect(&out);
    let param_pos = out.find(r#"(parameter "C")"#).expect(&out);
    let rest_pos = out.find("(rest #cmd)").expect(&out);
    assert!(
        style_pos < flags_pos
            && flags_pos < flag_pos
            && flag_pos < param_pos
            && param_pos < rest_pos,
        "unexpected order: {out}"
    );
}

#[test]
fn fmt_multi_file_one_parse_error_exits_two() {
    let good = write_config(
        r#"(rule "echo" (allow))
"#,
    );
    let bad = write_config("(rule \"unterm\n");
    let good_path = good.path().to_path_buf();
    let bad_path = bad.path().to_path_buf();

    may_i_cmd()
        .args([
            "fmt",
            &good_path.display().to_string(),
            &bad_path.display().to_string(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("parse error"));
}

#[test]
fn fmt_readonly_file_skipped_with_warning() {
    // Two files: the first read-only with a content that would change, the
    // second writable. The read-only one is skipped with a warning; the
    // writable one is formatted.
    let ro = write_config(
        r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#,
    );
    let rw = write_config(
        r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#,
    );

    let mut perms = std::fs::metadata(ro.path()).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(ro.path(), perms).unwrap();

    let result = may_i_cmd()
        .args([
            "fmt",
            &ro.path().display().to_string(),
            &rw.path().display().to_string(),
        ])
        .assert()
        .stderr(predicate::str::contains("not writable"));

    // Restore permissions so tempfile cleanup works on macOS.
    // Use PermissionsExt explicitly: set_readonly(false) is world-writable,
    // which clippy correctly flags. We want the original 0o644 mode back.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(ro.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    drop(result);

    let rw_text = std::fs::read_to_string(rw.path()).unwrap();
    let style_pos = rw_text.find("(style gnu)").expect(&rw_text);
    let flag_pos = rw_text.find(r#"(flag "v")"#).expect(&rw_text);
    assert!(
        style_pos < flag_pos,
        "rw file should be reformatted: {rw_text}"
    );
}

#[test]
fn fmt_walk_load_graph_formats_primary_and_loaded() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let inner_path = dir.path().join("inner.lisp");
    let primary_path = dir.path().join("primary.lisp");

    std::fs::write(
        &inner_path,
        r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#,
    )
    .unwrap();
    std::fs::write(
        &primary_path,
        format!(
            r#"(load "{}")
(rule "echo" (allow))
"#,
            inner_path.display()
        ),
    )
    .unwrap();

    may_i_cmd()
        .env("MAYI_CONFIG", &primary_path)
        .args(["fmt"])
        .assert()
        .success();

    let inner_text = std::fs::read_to_string(&inner_path).unwrap();
    let style_pos = inner_text.find("(style gnu)").expect(&inner_text);
    let flag_pos = inner_text.find(r#"(flag "v")"#).expect(&inner_text);
    assert!(
        style_pos < flag_pos,
        "loaded file reformatted: {inner_text}"
    );
}

#[test]
fn fmt_stdin_filter_writes_canonical_to_stdout() {
    let input = r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#;
    let cfg = write_config("");
    let output = may_i(&cfg)
        .args(["fmt"])
        .write_stdin(input)
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let style_pos = stdout.find("(style gnu)").expect(&stdout);
    let flag_pos = stdout.find(r#"(flag "v")"#).expect(&stdout);
    let param_pos = stdout.find(r#"(parameter "C")"#).expect(&stdout);
    assert!(
        style_pos < flag_pos && flag_pos < param_pos,
        "got: {stdout}"
    );
}

#[test]
fn fmt_stdin_explicit_dash_reads_stdin() {
    let input = r#"(check (deny "rm") (allow "ls"))
"#;
    let cfg = write_config("");
    let output = may_i(&cfg)
        .args(["fmt", "-"])
        .write_stdin(input)
        .output()
        .expect("run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let deny_pos = stdout.find(r#"(deny "rm")"#).expect(&stdout);
    let allow_pos = stdout.find(r#"(allow "ls")"#).expect(&stdout);
    assert!(
        deny_pos < allow_pos,
        "check cases preserve source order: {stdout}"
    );
}

#[test]
fn fmt_mixed_dash_and_paths_rejected() {
    let cfg = write_config("");
    may_i(&cfg)
        .args(["fmt", "-", "other.lisp"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("mixed"));
}

#[test]
fn fmt_check_clean_exits_zero() {
    // Already in canonical form: rule body is broken to a new line (the
    // pretty-printer's required indent for rule).
    let cfg = write_config("(rule \"echo\"\n  (allow))\n");
    may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .code(0);
}

#[test]
fn fmt_check_would_change_exits_one() {
    let cfg = write_config(
        r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#,
    );
    may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .code(1);
    // File on disk should be unchanged.
    let content = read_file(&cfg);
    assert!(content.starts_with(r#"(parser "git" (parameter "C")"#));
}

#[test]
fn fmt_check_parse_error_exits_two() {
    let cfg = write_config("(unclosed\n");
    may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .code(2);
}

#[test]
fn fmt_check_stdin_would_change_exits_one() {
    let cfg = write_config("");
    let input = r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#;
    let output = may_i(&cfg)
        .args(["fmt", "--check"])
        .write_stdin(input)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty in --check mode"
    );
}

#[test]
fn fmt_check_multifile_returns_highest_severity() {
    let clean = write_config(
        r#"(rule "echo" (allow))
"#,
    );
    let dirty = write_config(
        r#"(parser "git" (parameter "C") (flag "v") (style gnu))
"#,
    );
    let bad = write_config("(unterm\n");
    may_i_cmd()
        .args([
            "fmt",
            "--check",
            &clean.path().display().to_string(),
            &dirty.path().display().to_string(),
            &bad.path().display().to_string(),
        ])
        .assert()
        .code(2);
}

#[test]
fn fmt_legacy_syntax_warns_and_formats() {
    // (effect :allow …) is legacy; canonical is (allow …). The fmt command
    // does NOT rewrite, but emits a stderr warning.
    let cfg = write_config(
        r#"(rule "echo" (effect :allow))
"#,
    );
    let cfg_path = cfg.path().to_path_buf();

    let result = may_i(&cfg)
        .args(["fmt", &cfg_path.display().to_string()])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("legacy syntax"))
        .stderr(predicate::str::contains("may-i migrate"));

    drop(result);

    let after = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        after.contains(":allow"),
        "legacy form preserved (no semantic rewrite): {after}"
    );
}

#[test]
fn fmt_legacy_syntax_stdin_warns_with_stdin_marker() {
    let cfg = write_config("");
    let output = may_i(&cfg)
        .args(["fmt"])
        .write_stdin(
            r#"(rule "echo" (effect :allow))
"#,
        )
        .output()
        .expect("run");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("<stdin>"),
        "stderr should cite <stdin>: {stderr}"
    );
    assert!(
        stderr.contains("legacy"),
        "stderr should warn about legacy: {stderr}"
    );
}

#[test]
fn fmt_check_legacy_with_noncanonical_whitespace_exits_one() {
    // Non-canonical whitespace AND legacy syntax → fmt would change → exit 1
    // with warning.
    let cfg = write_config("(rule \"echo\"   (effect :allow))\n");
    let result = may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("legacy"));
    drop(result);
}

#[test]
fn fmt_comments_only_file_preserved_on_disk() {
    let cfg = write_config(";; just a top comment\n;; another\n\n;; trailer\n");
    let before = read_file(&cfg);
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .code(0);
    let after = read_file(&cfg);
    assert_eq!(before, after, "comments-only file must be byte-identical");
}

#[test]
fn fmt_comments_only_stdin_passes_through() {
    let cfg = write_config("");
    let input = ";; a\n;; b\n\n;; c\n";
    let output = may_i(&cfg)
        .args(["fmt"])
        .write_stdin(input)
        .output()
        .expect("run");
    assert!(output.status.success(), "exit 0 expected");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        input,
        "stdout must match stdin byte-for-byte"
    );
}

#[test]
fn fmt_check_comments_only_exits_zero_with_empty_stdout() {
    let cfg = write_config(";; comment only\n;; second line\n");
    let output = may_i(&cfg)
        .args(["fmt", "--check", &cfg.path().display().to_string()])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "exit 0 for clean input");
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty in --check mode"
    );
}

#[test]
fn fmt_whitespace_only_file_preserved_on_disk() {
    let cfg = write_config("\n  \n\t\n\n");
    let before = read_file(&cfg);
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .code(0);
    let after = read_file(&cfg);
    assert_eq!(before, after, "whitespace-only file must be byte-identical");
}

#[test]
fn fmt_preserves_trailing_newline_state_on_stdin() {
    let cfg = write_config("");
    // Input has trailing newline.
    let with_nl = "(rule \"echo\" (allow))\n";
    let output = may_i(&cfg)
        .args(["fmt"])
        .write_stdin(with_nl)
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&output.stdout);
    assert!(s.ends_with('\n'), "trailing newline preserved: {s:?}");

    // Input without trailing newline.
    let without_nl = "(rule \"echo\" (allow))";
    let output = may_i(&cfg)
        .args(["fmt"])
        .write_stdin(without_nl)
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&output.stdout);
    assert!(!s.ends_with('\n'), "no trailing newline preserved: {s:?}");
}

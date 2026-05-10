// Integration tests for the `fmt` subcommand.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{may_i, write_config};
use predicates::prelude::*;
use tempfile::NamedTempFile;

fn read_file(f: &NamedTempFile) -> String {
    std::fs::read_to_string(f.path()).expect("read")
}

#[test]
fn fmt_single_file_rewrites_in_place() {
    // Parser body order is canonicalised: style first, flag block, parameter
    // block, tail last. Source has them out of order.
    let cfg = write_config(
        r#"(parser "git" (parameter "C") (flag "v") (style gnu) (tail (after :flags)))
"#,
    );
    may_i(&cfg)
        .args(["fmt", &cfg.path().display().to_string()])
        .assert()
        .success();

    let out = read_file(&cfg);
    let style_pos = out.find("(style gnu)").expect(&out);
    let flag_pos = out.find(r#"(flag "v")"#).expect(&out);
    let param_pos = out.find(r#"(parameter "C")"#).expect(&out);
    let tail_pos = out.find("(tail").expect(&out);
    assert!(
        style_pos < flag_pos && flag_pos < param_pos && param_pos < tail_pos,
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

    cargo_bin_cmd!("may-i")
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

    let result = cargo_bin_cmd!("may-i")
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

    cargo_bin_cmd!("may-i")
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
    let allow_pos = stdout.find(r#"(allow "ls")"#).expect(&stdout);
    let deny_pos = stdout.find(r#"(deny "rm")"#).expect(&stdout);
    assert!(allow_pos < deny_pos, "check cases sorted: {stdout}");
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
    cargo_bin_cmd!("may-i")
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

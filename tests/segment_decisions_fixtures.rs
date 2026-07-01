// Step 1.1 fixtures — capture `evaluate_with_colorization` output for
// representative inputs. The CLI display path must remain byte-identical
// across the engine-segment-decisions refactor.

use std::path::PathBuf;

use may_i::cmd_eval::evaluate_with_colorization;
use may_i_core::ContextFacts;

mod common;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/segment_decisions")
        .join(name)
}

fn run(command: &str) -> (String, String) {
    let cfg = common::write_config(
        r#"
(rule "echo" (allow))
(rule "cat" (allow))
(rule "grep" (allow))
(rule "rm" (deny "rm denied"))
"#,
    );
    let loaded = may_i_config::load_and_resolve(Some(cfg.path())).expect("load config");
    let context = ContextFacts::default();
    let (result, _traces, colored, _audit) =
        evaluate_with_colorization(command, &loaded, &context, &may_i_core::EntryEnv::empty())
            .expect("evaluate_with_colorization");
    let mut buf = Vec::new();
    may_i_output::write_line(
        &mut buf,
        &colored,
        &may_i_output::Terminal::new(200).with_color(true),
    );
    let colored = String::from_utf8(buf).unwrap().trim_end().to_string();
    (result.decision.to_string(), colored)
}

fn assert_fixture(name: &str, command: &str) {
    let (decision, colored) = run(command);
    let actual = format!("decision: {decision}\ncolored: {colored}\n");
    let path = fixture_path(name);
    if std::env::var("UPDATE_FIXTURES").is_ok() || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        std::fs::write(&path, &actual).expect("write fixture");
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("read fixture");
    assert_eq!(
        actual, expected,
        "fixture mismatch for {name}: rerun with UPDATE_FIXTURES=1 to refresh"
    );
}

#[test]
fn fixture_single_command() {
    assert_fixture("single_command.txt", "echo hi");
}

#[test]
fn fixture_compound_and() {
    assert_fixture("compound_and.txt", "echo a && rm -rf /");
}

#[test]
fn fixture_compound_semicolon() {
    assert_fixture("compound_semicolon.txt", "echo a; echo b");
}

#[test]
fn fixture_pipe() {
    assert_fixture("pipe.txt", "cat file | grep foo");
}

#[test]
fn fixture_embedded_substitution() {
    assert_fixture("embedded_substitution.txt", "echo $(rm)");
}

#[test]
fn fixture_dynamic_editor() {
    assert_fixture("dynamic_editor.txt", "$EDITOR file.txt");
}

#[test]
fn fixture_malformed_unterminated_quote() {
    assert_fixture("malformed_unterminated_quote.txt", r#"echo "hello"#);
}

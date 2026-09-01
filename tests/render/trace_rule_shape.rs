// Regression test for trace-faithful-rule-shape.
//
// Asserts the rendered trace uses the source-DSL surface for rules:
// command at head (string atom or `(or …)`), body forms direct children of
// `(rule …)`, no synthetic `(command …)` / `(args …)` / `(context …)` wrappers,
// no lift of when/unless predicates into a synthetic context sibling.

use std::io::Write;

use may_i::cmd_eval::evaluate_with_colorization;
use may_i::output::EvalOutput;
use may_i::pipeline::CommandPipeline;
use may_i::trust::InvocationTrust;
use tempfile::NamedTempFile;

fn render_trace(config_source: &str, command: &str) -> String {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(config_source.as_bytes()).expect("write");
    let path = tmp.path().to_path_buf();

    let mut loaded = may_i_config::load(&path).expect("load config");
    let resolved =
        may_i_config::resolve::validate_and_resolve(&loaded.config.rules, &loaded.config.defines)
            .expect("resolve");
    loaded.config.rules = resolved;

    let context = may_i_core::ContextFacts::default();
    let (result, traces, colored_command, _audit) = evaluate_with_colorization(
        command,
        &loaded,
        &context,
        &may_i_core::EntryEnv::empty(),
        may_i_shell_parser::Dialect::Bash,
    )
    .unwrap();

    let trust = InvocationTrust::with_loader(false, Box::new(|| None));
    let pipeline = CommandPipeline::with_trust(loaded, false, trust);
    let mut buf = Vec::new();
    EvalOutput {
        config_path: &path,
        trace_entries: &traces,
        command,
        colored_command: &colored_command,
        eval_result: &result,
    }
    .render(&mut buf, pipeline.terminal());

    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn rule_shape_when_body_renders_literally() {
    let config = r#"
(rule "terragrunt"
  (when (positional "hcl") (allow "safe")))
"#;
    let out = render_trace(config, "terragrunt hcl");

    assert!(
        out.contains(r#"(rule "terragrunt""#),
        "expected literal command at rule head, got:\n{}",
        out
    );
    assert!(
        out.contains("(when (positional"),
        "expected `when` body literal, got:\n{}",
        out
    );
    assert!(
        !out.contains(r#"(command "terragrunt")"#),
        "unexpected synthetic (command …) wrapper, got:\n{}",
        out
    );
    assert!(
        !out.contains("(args ("),
        "unexpected synthetic (args …) wrapper, got:\n{}",
        out
    );
    assert!(
        !out.contains("(context (positional"),
        "unexpected synthetic (context …) lift, got:\n{}",
        out
    );
}

#[test]
fn rule_shape_or_alternation_renders_at_head() {
    let config = r#"
(rule (or "a" "b") (allow))
"#;
    let out = render_trace(config, "a");

    assert!(
        out.contains(r#"(rule (or "a""#),
        "expected `or` alternation at rule head, got:\n{}",
        out
    );
    assert!(
        !out.contains("(command (or"),
        "unexpected synthetic (command (or …)) wrapper, got:\n{}",
        out
    );
    assert!(
        !out.contains("(args ("),
        "unexpected synthetic (args …) wrapper, got:\n{}",
        out
    );
}

// Snapshot tests for config error diagnostics, organized by error category.
//
// Each test feeds invalid input to the config parser and snapshots the
// rendered miette diagnostic so regressions in formatting, labels, or
// span placement are caught automatically.
//
// Run: cargo test --test config_error_snapshots
// Review: cargo insta review

use miette::GraphicalReportHandler;

fn render_error(input: &str) -> String {
    let err = may_i_config::parse::parse(input, "<test>")
        .expect_err("expected a parse error");
    let handler = GraphicalReportHandler::new_themed(miette::GraphicalTheme::unicode_nocolor());
    let mut out = String::new();
    handler.render_report(&mut out, err.as_ref()).unwrap();
    out
}

// ── S-expression tokenizer & structural errors ──────────────────────

mod sexpr {
    use super::*;

    #[test]
    fn unterminated_string() {
        insta::assert_snapshot!(render_error("(rule \"hello"));
    }

    #[test]
    fn unexpected_char() {
        insta::assert_snapshot!(render_error("[rule]"));
    }

    #[test]
    fn unclosed_paren_eof() {
        insta::assert_snapshot!(render_error("(rule foo"));
    }

    #[test]
    fn unclosed_paren_eof_empty() {
        insta::assert_snapshot!(render_error("("));
    }

    #[test]
    fn extra_close() {
        insta::assert_snapshot!(render_error("(a b))"));
    }

    #[test]
    fn extra_close_bare() {
        insta::assert_snapshot!(render_error(")"));
    }

    #[test]
    fn sibling_absorbed() {
        insta::assert_snapshot!(render_error("(rule foo\n(other bar)"));
    }
}

// ── DSL-level semantic errors ───────────────────────────────────────

mod config {
    use super::*;

    #[test]
    fn top_level_atom() {
        insta::assert_snapshot!(render_error("hello"));
    }

    #[test]
    fn empty_form() {
        insta::assert_snapshot!(render_error("()"));
    }

    #[test]
    fn unknown_form() {
        insta::assert_snapshot!(render_error("(bogus \"x\")"));
    }

    #[test]
    fn rule_missing_command() {
        insta::assert_snapshot!(render_error("(rule (effect :allow))"));
    }

    #[test]
    fn unknown_effect_keyword() {
        insta::assert_snapshot!(render_error("(rule (command \"x\") (effect :yolo))"));
    }
}

// Snapshot tests for wrapper DSL forms.
//
// Valid-form tests snapshot the parsed Wrapper structs (Debug) so that changes
// to the data model are immediately visible.
//
// Error-form tests snapshot the rendered miette diagnostic so that changes to
// error messages, spans, or help text are caught.
//
// Run: cargo test --test wrapper_snapshots
// Review: cargo insta review

use miette::GraphicalReportHandler;

fn parse_wrappers(input: &str) -> Vec<may_i::types::Wrapper> {
    may_i::config_parse::parse(input, "<test>")
        .expect("expected valid config")
        .wrappers
}

fn render_error(input: &str) -> String {
    let err = may_i::config_parse::parse(input, "<test>")
        .expect_err("expected a parse error");
    let handler = GraphicalReportHandler::new_themed(miette::GraphicalTheme::unicode_nocolor());
    let mut out = String::new();
    handler.render_report(&mut out, err.as_ref()).unwrap();
    out
}

// ── Valid forms ──────────────────────────────────────────────────────

mod valid {
    use super::*;

    #[test]
    fn bare_capture_keyword() {
        // (wrapper "nohup" :command+args) — shorthand for after-flags style
        insta::assert_debug_snapshot!(parse_wrappers(r#"(wrapper "nohup" :command+args)"#));
    }

    #[test]
    fn bare_capture_keyword_command_only() {
        insta::assert_debug_snapshot!(parse_wrappers(r#"(wrapper "x" :command)"#));
    }

    #[test]
    fn bare_capture_keyword_args_only() {
        insta::assert_debug_snapshot!(parse_wrappers(r#"(wrapper "x" :args)"#));
    }

    #[test]
    fn positional_no_patterns() {
        // Explicit form equivalent to bare :command+args
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "nohup" (positional :command+args))"#
        ));
    }

    #[test]
    fn positional_wildcard() {
        // (wrapper "ssh" (positional * :command+args))
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "ssh" (positional * :command+args))"#
        ));
    }

    #[test]
    fn positional_literal() {
        // Single literal pattern before capture
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "docker" (positional "exec" :command+args))"#
        ));
    }

    #[test]
    fn positional_multiple_literals() {
        // Multiple literal patterns before capture
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "x" (positional "a" "b" :command+args))"#
        ));
    }

    #[test]
    fn positional_or_pattern() {
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "x" (positional (or "foo" "bar") :command+args))"#
        ));
    }

    #[test]
    fn flag_double_dash() {
        // (wrapper "terragrunt" (flag "--" :command+args))
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "terragrunt" (flag "--" :command+args))"#
        ));
    }

    #[test]
    fn flag_named() {
        // (wrapper "nix-shell" (flag "--run" :command+args))
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "nix-shell" (flag "--run" :command+args))"#
        ));
    }

    #[test]
    fn positional_validate_then_flag() {
        // (wrapper "mise" (positional "exec") (flag "--" :command+args))
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "mise" (positional "exec") (flag "--" :command+args))"#
        ));
    }

    #[test]
    fn positional_or_then_flag() {
        // (wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))"#
        ));
    }

    #[test]
    fn multiple_wrappers() {
        // Multiple wrappers in one config
        insta::assert_debug_snapshot!(parse_wrappers(
            r#"
            (wrapper "nohup"      :command+args)
            (wrapper "ssh"        (positional * :command+args))
            (wrapper "mise"       (positional "exec") (flag "--" :command+args))
            "#
        ));
    }
}

// ── Error forms ──────────────────────────────────────────────────────

mod errors {
    use super::*;

    #[test]
    fn missing_command() {
        insta::assert_snapshot!(render_error("(wrapper)"));
    }

    #[test]
    fn missing_capture() {
        // Wrapper with no capture keyword at all
        insta::assert_snapshot!(render_error(r#"(wrapper "nohup")"#));
    }

    #[test]
    fn positional_with_no_capture() {
        // Positional step but capture keyword omitted
        insta::assert_snapshot!(render_error(
            r#"(wrapper "x" (positional "sub"))"#
        ));
    }

    #[test]
    fn duplicate_capture_positional_then_flag() {
        insta::assert_snapshot!(render_error(
            r#"(wrapper "x" (positional "a" :command+args) (flag "--" :command+args))"#
        ));
    }

    #[test]
    fn duplicate_capture_two_bare_keywords() {
        insta::assert_snapshot!(render_error(
            r#"(wrapper "x" :command+args :command+args)"#
        ));
    }

    #[test]
    fn flag_missing_capture() {
        // (flag ...) with only the name, no capture keyword
        insta::assert_snapshot!(render_error(r#"(wrapper "x" (flag "--"))"#));
    }

    #[test]
    fn flag_extra_element() {
        insta::assert_snapshot!(render_error(
            r#"(wrapper "x" (flag "--" :command+args "extra"))"#
        ));
    }

    #[test]
    fn flag_bad_capture_keyword() {
        insta::assert_snapshot!(render_error(r#"(wrapper "x" (flag "--" :bogus))"#));
    }

    #[test]
    fn unknown_element() {
        insta::assert_snapshot!(render_error(r#"(wrapper "x" (bogus "y"))"#));
    }

    #[test]
    fn unexpected_bare_atom() {
        // Bare atom that is not a capture keyword
        insta::assert_snapshot!(render_error(r#"(wrapper "x" something-else)"#));
    }

    #[test]
    fn list_as_command() {
        // The command must be a string atom, not a list
        insta::assert_snapshot!(render_error(r#"(wrapper (foo "bar") :command+args)"#));
    }
}

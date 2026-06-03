//! Golden-output snapshots for representative config-load diagnostics
//! (task 7.5). These render through the same miette path as production
//! (`ConfigError`), locking the format and the user-facing vocabulary.

use may_i_config::{ConfigError, parse_config};

fn render(src: &str) -> String {
    let raw = parse_config(src).expect_err("expected a parse error");
    let err = ConfigError::from_raw(raw, src, "config.lisp");
    let mut out = String::new();
    miette::GraphicalReportHandler::new_themed(miette::GraphicalTheme::unicode_nocolor())
        .render_report(&mut out, &err)
        .unwrap();
    out
}

#[test]
fn unknown_rule_body_form() {
    insta::assert_snapshot!(render("(rule \"git\" (frobnicate))"));
}

#[test]
fn legacy_effect_form_retired() {
    insta::assert_snapshot!(render("(rule \"git\" (effect :allow))"));
}

#[test]
fn unknown_parser_body_item() {
    insta::assert_snapshot!(render("(parser \"git\" (style gnu) (wat \"v\"))"));
}

#[test]
fn many_till_outside_parser_body() {
    insta::assert_snapshot!(render(
        "(rule \"find\" (when (matches? #a (many-till \";\")) (allow)))"
    ));
}

#[test]
fn shape_form_outside_parameter() {
    insta::assert_snapshot!(render(
        "(parser \"x\" (style gnu) (flags posix) (positional #p (set #q)))"
    ));
}

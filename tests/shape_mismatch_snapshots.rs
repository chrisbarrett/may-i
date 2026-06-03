//! Golden-output snapshots for each shape-mismatch family (task 6.6).
//!
//! Each case renders a config that triggers exactly one mismatch and
//! pins the Elm-style output. Colour is disabled for stable diffs.

use may_i::shape_diag::build_report;
use may_i_config::parse_config;
use may_i_engine::shape_check::check_config;

fn render(src: &str) -> String {
    let config = parse_config(src).expect("config parses");
    let mismatches = check_config(&config);
    let report = build_report(&mismatches, src, "config.lisp").expect("expected a mismatch");
    let mut out = String::new();
    miette::GraphicalReportHandler::new_themed(miette::GraphicalTheme::unicode_nocolor())
        .render_report(&mut out, report.as_ref())
        .unwrap();
    out
}

#[test]
fn every_on_token() {
    insta::assert_snapshot!(render(
        "(parser \"xargs\" (style gnu) (flags posix) (parameter \"n\" #procs) (rest #cmd))\n\
         (rule \"xargs\" (when (every? #procs (regex \"^[0-9]+$\")) (allow)))"
    ));
}

#[test]
fn authorise_on_collection() {
    insta::assert_snapshot!(render(
        "(parser \"ssh\" (style gnu) (flags posix) (parameter \"o\" (set #opts)))\n\
         (rule \"ssh\" (authorise #opts))"
    ));
}

#[test]
fn some_on_command() {
    insta::assert_snapshot!(render(
        "(parser \"bash\" (style gnu) (flags posix) (parameter \"c\" (command #cmd)))\n\
         (rule \"bash\" (when (some? #cmd (regex \"rm\")) (deny)))"
    ));
}

#[test]
fn matches_on_count() {
    insta::assert_snapshot!(render(
        "(parser \"curl\" (style gnu) (flags permute) (flag \"v\" (count #verbosity)))\n\
         (rule \"curl\" (when (matches? #verbosity (regex \"3\")) (ask)))"
    ));
}

#[test]
fn authorise_on_count() {
    insta::assert_snapshot!(render(
        "(parser \"curl\" (style gnu) (flags permute) (flag \"v\" (count #verbosity)))\n\
         (rule \"curl\" (authorise #verbosity))"
    ));
}

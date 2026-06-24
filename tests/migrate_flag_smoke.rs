// Smoke test: end-to-end migration converts v1 flag matchers.
// Test-only debug output; the workspace `print_stdout` deny targets the
// production sink, not test scaffolding.
#![allow(clippy::print_stdout)]

use may_i_config::migrate;

#[test]
fn migrate_anywhere_dash_x_to_flag_x() {
    let input = r#"(rule (command "rm") (args (anywhere "-r")) (effect :deny))"#;
    let (nodes, _) = may_i_sexpr::parse_cst(input);
    let migrated = migrate::migrate_forms(nodes);
    let out: String = migrated.iter().map(|n| n.serialize()).collect();
    assert!(out.contains(r#"(flag "r")"#), "got: {out}");
}

#[test]
fn migrate_forbidden_dash_x_to_not_flag() {
    let input = r#"(rule (command "rm") (args (forbidden "-r")) (effect :allow))"#;
    let (nodes, _) = may_i_sexpr::parse_cst(input);
    let migrated = migrate::migrate_forms(nodes);
    let out: String = migrated.iter().map(|n| n.serialize()).collect();
    assert!(out.contains(r#"(not (flag "r"))"#), "got: {out}");
}

#[test]
fn migrate_v1_fixture_complex_rule() {
    let input = r#"(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (effect :deny "Recursive deletion from root"))"#;
    let (nodes, _) = may_i_sexpr::parse_cst(input);
    let migrated = migrate::migrate_forms(nodes);
    let out: String = migrated.iter().map(|n| n.serialize()).collect();
    println!("Migrated: {out}");
    assert!(out.contains(r#"(flag "r")"#), "got: {out}");
    assert!(out.contains(r#"(flag "recursive")"#), "got: {out}");
}

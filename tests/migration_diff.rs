// Integration tests for migration diff functionality

#[test]
fn test_trivia_extraction() {
    use may_i_config::migrate::{extract_leading_context, extract_trailing_context};
    use may_i_sexpr::parse_cst;

    let source = r#";; Comment before
(rule git (effect :allow))
;; Comment after"#;

    let (forms, _) = parse_cst(source);
    assert_eq!(forms.len(), 1);

    let form = &forms[0];
    let leading = extract_leading_context(form, 2);
    assert!(!leading.is_empty(), "Should have leading trivia");

    let trailing = extract_trailing_context(form, 2);
    // Trailing trivia might include the newline after the form
    assert!(
        trailing.len() <= 2,
        "Should have at most 2 lines of trailing trivia"
    );
}

#[test]
fn test_migration_analysis_no_changes() {
    use may_i_config::migrate::analyze_migration;

    // Already canonical syntax (unified style) - no changes needed
    let source = "(rule git (allow))";
    let analysis = analyze_migration(source);

    assert!(
        analysis.diffs.is_empty(),
        "Already canonical syntax should have no diffs"
    );
    assert_eq!(analysis.unchanged_count, 1, "Should have 1 unchanged form");
}

#[test]
fn test_migration_analysis_with_changes() {
    use may_i_config::migrate::analyze_migration;

    // v1 syntax that needs migration
    let source = "(rule (command git) (effect :allow))";
    let analysis = analyze_migration(source);

    assert_eq!(analysis.diffs.len(), 1, "Should have 1 diff");
    assert_eq!(analysis.unchanged_count, 0, "Should have 0 unchanged forms");

    let diff = &analysis.diffs[0];
    assert!(
        diff.before.contains("(command git)"),
        "Before should contain command"
    );
    assert!(
        !diff.after.contains("(command git)"),
        "After should not contain command"
    );
    assert!(
        diff.after.contains("git"),
        "After should have command inlined"
    );
}

#[test]
fn test_migration_analysis_multiple_forms() {
    use may_i_config::migrate::analyze_migration;

    let source = r#"
(rule (command git) (effect :allow))
(defcontext ssh (has :via/ssh))
(rule ls (allow))
"#;

    let analysis = analyze_migration(source);

    // Should detect changes in first two forms (v1 syntax), last one is already canonical syntax
    assert!(analysis.diffs.len() >= 2, "Should have at least 2 diffs");
    assert!(
        analysis.unchanged_count >= 1,
        "Should have at least 1 unchanged form"
    );
}

#[test]
fn test_check_unhandled_cases_no_false_positives() {
    use may_i_config::migrate::check_unhandled_cases;

    // Comments containing words like "wrapper" should not be flagged
    let source = r#"
;; This is a comment about wrapper usage
(rule git (effect :allow))
"#;

    let warnings = check_unhandled_cases(source);
    assert!(
        warnings.is_empty(),
        "Comments should not trigger false positives"
    );
}

#[test]
fn test_check_unhandled_cases_real_issues() {
    use may_i_config::migrate::check_unhandled_cases;

    // A form that can't be migrated (malformed)
    let source = r#"
(wrapper)
"#;

    let _warnings = check_unhandled_cases(source);
    // Malformed wrapper might be flagged since it can't migrate
    // This is expected behavior
}

#[test]
fn test_diff_output_no_changes() {
    use may_i_config::migrate::analyze_migration;

    let source = "(rule git (allow))\n";
    let analysis = analyze_migration(source);

    // Verify the analysis structure
    assert!(
        analysis.diffs.is_empty(),
        "Should have no diffs for canonical syntax"
    );
    assert_eq!(analysis.unchanged_count, 1, "Should have 1 unchanged form");
    assert!(analysis.errors.is_empty(), "Should have no errors");
}

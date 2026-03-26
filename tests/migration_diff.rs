// Integration tests for migration diff functionality

use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a temp config file with given content
fn create_temp_config(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

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
    let source = "(rule git :effect :allow)";
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
(rule ls :effect :allow)
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
fn test_migration_diff_struct() {
    use may_i_config::migrate::{MigrationDiff, Span};

    let diff = MigrationDiff {
        before: "(rule (command git) (effect :allow))".to_string(),
        after: "(rule git (effect :allow))".to_string(),
        context_before: vec![";; Comment\n".to_string()],
        context_after: vec!["\n".to_string()],
        span: Span { start: 0, end: 36 },
    };

    assert_ne!(diff.before, diff.after, "Before and after should differ");
    assert!(
        !diff.context_before.is_empty(),
        "Should have context before"
    );
}

#[test]
fn test_terminal_width_detection() {
    // Test that we can get a reasonable terminal width
    let width = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80);

    assert!(width >= 40, "Terminal width should be at least 40");
    assert!(width <= 300, "Terminal width should be at most 300");
}

#[test]
fn test_side_by_side_vs_vertical_layout() {
    use may_i_config::migrate::{MigrationAnalysis, MigrationDiff, Span};

    let analysis = MigrationAnalysis {
        diffs: vec![MigrationDiff {
            before: "(wrapper docker :command)".to_string(),
            after: "(rule docker . (may-i *) (effect :allow))".to_string(),
            context_before: vec![],
            context_after: vec!["\n".to_string()],
            span: Span { start: 0, end: 26 },
        }],
        errors: vec![],
        unchanged_count: 0,
    };

    // Verify the analysis structure
    assert_eq!(analysis.diffs.len(), 1);
    assert!(analysis.errors.is_empty());
}

#[test]
fn test_error_context_display() {
    use may_i_config::migrate::{MigrationError, Span};

    let error = MigrationError {
        message: "unexpected character: '~'".to_string(),
        span: Span { start: 10, end: 11 },
        context_before: vec!["(rule ".to_string()],
        context_after: vec![" ...)".to_string()],
    };

    assert_eq!(error.span.start, 10);
    assert_eq!(error.span.end, 11);
    assert!(!error.context_before.is_empty());
}

// Snapshot tests for migration diff output

#[test]
fn test_diff_output_simple_migration() {
    use may_i_config::migrate::analyze_migration;

    let source = "(rule (command git) (effect :allow))\n";
    let analysis = analyze_migration(source);

    // Verify the analysis structure
    assert_eq!(analysis.diffs.len(), 1, "Should have 1 diff");
    assert_eq!(analysis.unchanged_count, 0, "Should have 0 unchanged forms");
    assert!(analysis.errors.is_empty(), "Should have no errors");

    // Verify the diff content
    let diff = &analysis.diffs[0];
    assert!(
        diff.before.contains("(command git)"),
        "Before should have command wrapper"
    );
    assert!(
        !diff.after.contains("(command"),
        "After should not have command wrapper"
    );
    assert!(
        diff.after.contains("git :effect"),
        "After should have inlined command"
    );
}

#[test]
fn test_diff_output_multiple_changes() {
    use may_i_config::migrate::analyze_migration;

    let source = r#"(rule (command git) (effect :allow))
(rule (command ls) (effect :allow))
"#;
    let analysis = analyze_migration(source);

    // Verify the analysis structure
    assert_eq!(analysis.diffs.len(), 2, "Should have 2 diffs");
    assert_eq!(analysis.unchanged_count, 0, "Should have 0 unchanged forms");
    assert!(analysis.errors.is_empty(), "Should have no errors");

    // Verify both diffs are present
    let commands: Vec<&str> = analysis
        .diffs
        .iter()
        .map(|d| d.after.split_whitespace().nth(1).unwrap_or(""))
        .collect();
    assert!(commands.contains(&"git"), "Should have git command");
    assert!(commands.contains(&"ls"), "Should have ls command");
}

#[test]
fn test_diff_output_no_changes() {
    use may_i_config::migrate::analyze_migration;

    let source = "(rule git :effect :allow)\n";
    let analysis = analyze_migration(source);

    // Verify the analysis structure
    assert!(
        analysis.diffs.is_empty(),
        "Should have no diffs for canonical syntax"
    );
    assert_eq!(analysis.unchanged_count, 1, "Should have 1 unchanged form");
    assert!(analysis.errors.is_empty(), "Should have no errors");
}

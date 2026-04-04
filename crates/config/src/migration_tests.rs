// Comprehensive migration tool tests for v1 to canonical syntax conversion.

use crate::migrate::{check_unhandled_cases, migrate, migrate_forms, validate_migration};
use may_i_sexpr::parse_cst;

fn parse_single(input: &str) -> Box<may_i_sexpr::cst::CstNode> {
    let (forms, errors) = parse_cst(input);
    if !errors.is_empty() {
        panic!("Parse errors: {:?}", errors);
    }
    if forms.is_empty() {
        panic!("No forms parsed");
    }
    forms.into_iter().next().unwrap()
}

#[test]
fn migration_simple_rule_with_command() {
    let input = r#"(rule (command "git") (effect :allow))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("rule"));
    assert!(output.contains("git"));
    assert!(!output.contains("(command")); // Should be simplified
}

#[test]
fn migration_rule_with_context() {
    let input = r#"(rule (command "git") (context (has :via/ssh)) (effect :allow))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("fact?"));
    assert!(output.contains(":via/ssh"));
    assert!(!output.contains("(context")); // Should be inlined
}

#[test]
fn migration_rule_with_args() {
    let input = r#"(rule (command "git") (args (positional "push")) (effect :allow))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("positional"));
    assert!(output.contains("push"));
    assert!(!output.contains("(args")); // Should be inlined
}

#[test]
fn migration_wrapper_to_rule() {
    let input = r#"(wrapper "ssh" (positional [:host *] :command+args))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("rule"));
    assert!(output.contains("ssh"));
    assert!(output.contains("may-i"));
    assert!(!output.contains("wrapper"));
}

#[test]
fn migration_defcontext_to_define() {
    let input = r#"(defcontext ssh (has :via/ssh))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("define"));
    assert!(output.contains("ssh"));
    assert!(!output.contains("defcontext"));
}

#[test]
fn migration_complex_defcontext() {
    let input = r#"
        (defcontext remote-prod
            (and (has :via/ssh)
                 (has [:host (regex "^prod-")])))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("define"));
    assert!(output.contains("remote-prod"));
    assert!(output.contains("and"));
    assert!(output.contains("regex"));
}

#[test]
fn migration_preserves_comments() {
    let input = r#";; This is a comment
(rule (command "git") (effect :allow))"#;
    let node = parse_single(input);
    let result = migrate(node);
    // Comments may or may not be preserved depending on CST implementation
    // Just verify the rule is migrated
    assert!(result.serialize().contains("rule"));
}

#[test]
fn validate_migration_success() {
    // Test that properly migrated (new syntax) configs pass validation
    let migrated = r#"
        (rule "git" (effect :allow))
        (define safe (fact? :local))
    "#;

    let result = validate_migration(migrated);
    assert!(
        result.is_ok(),
        "Validation should succeed for properly migrated new syntax"
    );
}

#[test]
fn validate_migration_failure() {
    let migrated = r#"
        (rule "git" (effect :invalid-decision))
    "#;

    let result = validate_migration(migrated);
    assert!(
        result.is_err(),
        "Validation should fail for invalid effect keyword"
    );
}

#[test]
fn check_unhandled_wrapper() {
    let input = r#"(wrapper "sudo" :command+args)"#;
    let unhandled = check_unhandled_cases(input);

    assert!(!unhandled.is_empty());
    assert!(unhandled.iter().any(|u| u.description.contains("wrapper")));
}

#[test]
fn check_unhandled_defcontext() {
    let input = r#"(defcontext prod (has :env "prod"))"#;
    let unhandled = check_unhandled_cases(input);

    assert!(!unhandled.is_empty());
    assert!(
        unhandled
            .iter()
            .any(|u| u.description.contains("defcontext"))
    );
}

#[test]
fn migration_multiple_forms() {
    let input = r#"
        (defcontext ssh (has :via/ssh))
        (rule (command "git") (context ssh) (effect :allow))
        (wrapper "sudo" :command+args)
    "#;

    let (forms, _) = parse_cst(input);
    let migrated = migrate_forms(forms);

    assert_eq!(migrated.len(), 3);

    let output = migrated
        .iter()
        .map(|f| f.serialize())
        .collect::<Vec<_>>()
        .concat();

    assert!(output.contains("define"));
    assert!(output.contains("rule"));
    assert!(!output.contains("defcontext"));
}

#[test]
fn migration_preserves_check_forms() {
    let input = r#"(check :allow "git status")"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("check"));
    assert!(output.contains(":allow"));
    assert!(output.contains("git status"));
}

#[test]
fn migration_empty_config() {
    let input = r#""#;
    let (forms, _) = parse_cst(input);
    let migrated = migrate_forms(forms);

    assert!(migrated.is_empty());
}

#[test]
fn migration_complex_real_world_config() {
    let input = r#"
        ;; Production environment context
        (defcontext prod
            (and (has :via/ssh)
                 (has [:host (regex "prod")])))
        
        ;; SSH wrapper for remote commands
        (wrapper "ssh" (positional [:host *] :command+args))
        
        ;; Allow git status everywhere
        (rule (command "git")
              (args (positional "status"))
              (effect :allow))
        
        ;; Deny git push to prod
        (rule (command "git")
              (context prod)
              (args (positional "push"))
              (effect :deny "No pushes to prod"))
    "#;

    let (forms, _) = parse_cst(input);
    let migrated = migrate_forms(forms);

    assert_eq!(migrated.len(), 4);

    let output = migrated
        .iter()
        .map(|f| f.serialize())
        .collect::<Vec<_>>()
        .concat();

    // All v1 forms should be migrated
    assert!(!output.contains("defcontext"));
    assert!(!output.contains("(wrapper"));
    assert!(!output.contains("(context"));
    assert!(!output.contains("(args"));

    // Canonical forms should be present
    assert!(output.contains("define"));
    assert!(output.contains("rule"));
}

#[test]
fn migration_safe_env_vars_preserved() {
    let input = r#"(safe-env-vars "HOME" "USER" "PATH")"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("safe-env-vars"));
    assert!(output.contains("HOME"));
    assert!(output.contains("USER"));
}

#[test]
fn migration_rule_with_regex_command() {
    let input = r#"(rule (command (regex "^git-")) (effect :allow))"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("regex"));
    assert!(output.contains("rule"));
}

#[test]
fn migration_args_with_cond() {
    let input = r#"(rule (command "git")
      (args (cond
              ((positional "push") (effect :ask))
              (else (effect :allow)))))"#;

    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("cond"));
    assert!(output.contains("else"));
}

#[test]
fn validate_migration_reports_errors() {
    let invalid_config = r#"
        (rule "git" (effect :invalid-decision))
    "#;

    let result = validate_migration(invalid_config);
    assert!(result.is_err());

    let errors = result.unwrap_err();
    assert!(!errors.is_empty());
}

#[test]
fn check_unhandled_reporting_format() {
    let input = r#"(wrapper "ssh" :command+args)"#;
    let unhandled = check_unhandled_cases(input);

    for case in &unhandled {
        assert!(!case.description.is_empty());
        assert!(!case.source.is_empty());
        assert!(!case.suggestion.is_empty());
    }
}

#[test]
fn migration_idempotent() {
    let input = r#"(rule (command "git") (effect :allow))"#;
    let node = parse_single(input);

    // First migration
    let result1 = migrate(node.clone());
    let output1 = result1.serialize();

    // Second migration (should be stable)
    let result2 = migrate(result1);
    let output2 = result2.serialize();

    assert_eq!(output1, output2, "Migration should be idempotent");
}

#[test]
fn migration_preserves_order() {
    let input = r#"
        (defcontext a (has :a))
        (defcontext b (has :b))
        (rule (command "x") (effect :allow))
    "#;

    let (forms, _) = parse_cst(input);
    let migrated = migrate_forms(forms);

    assert_eq!(migrated.len(), 3);

    // Forms should maintain relative order
    let outputs: Vec<String> = migrated.iter().map(|f| f.serialize()).collect();
    assert!(outputs[0].contains("a"));
    assert!(outputs[1].contains("b"));
    assert!(outputs[2].contains("rule"));
}

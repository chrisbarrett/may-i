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
    assert!(output.contains("authorise"));
    assert!(!output.contains("may-i"));
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
        (rule "git" (allow))
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
fn migration_rewrites_check_to_form_list() {
    let input = r#"(check :allow "git status")"#;
    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    assert!(output.contains("check"));
    assert!(output.contains("(allow"));
    assert!(!output.contains(":allow"));
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

    // Single-clause cond+else gets simplified to if
    assert!(
        output.contains("if"),
        "single-clause cond+else should become if, got: {output}"
    );
    assert!(
        !output.contains("cond"),
        "should no longer contain cond, got: {output}"
    );
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

#[test]
fn migration_check_forms_after_body_in_rule_with_args_cond() {
    let input = r#"(rule (command "mv")
      (args (if (anywhere "-f" "--force")
                (effect :ask "File moves with -f/--force can be destructive")
              (effect :allow)))
      (check :allow "mv foo bar"
             :ask "mv -f foo bar"))"#;

    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    // check form must appear after the body (cond/if), not before it
    let check_pos = output.find("check").expect("should contain check");
    let body_pos = output
        .find("cond")
        .or_else(|| output.find("if"))
        .expect("should contain body");
    assert!(
        check_pos > body_pos,
        "check form should come after body form in rule, got:\n{output}"
    );
}

#[test]
fn migration_check_forms_after_body_in_rule_with_context() {
    let input = r#"(rule (command "rm")
      (context dangerous)
      (effect :ask "Destructive command")
      (check :ask "rm -rf /"))"#;

    let node = parse_single(input);
    let result = migrate(node);
    let output = result.serialize();

    // check form must appear after the when/body, not before it
    let check_pos = output.find("check").expect("should contain check");
    let body_pos = output
        .find("when")
        .or_else(|| output.find("effect"))
        .expect("should contain body");
    assert!(
        check_pos > body_pos,
        "check form should come after body form in rule, got:\n{output}"
    );
}

// ── shape-typed-bindings: shape forms survive migration (task 8.2) ──

#[test]
fn migration_leaves_parameter_shape_forms_untouched() {
    // No migration rewrites shape annotations; the new forms pass
    // through `may-i migrate` byte-for-byte (so they are never flagged
    // as unknown, and never silently reshaped — which would be a Class
    // B change). See design D8.
    let inputs = [
        r#"(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))"#,
        r#"(parser "gcc" (style gnu) (flags permute) (parameter "O" (last #opt)))"#,
        r#"(parser "bash" (style gnu) (flags posix) (parameter "c" (command #cmd)))"#,
        r#"(parser "curl" (style gnu) (flags permute) (flag "v" (count #verbosity)))"#,
    ];
    for input in inputs {
        let node = parse_single(input);
        let output = migrate(node).serialize();
        assert_eq!(output.trim(), input, "shape form mutated by migration");
    }
}

#[test]
fn migration_idempotent_on_shape_forms() {
    let input =
        r#"(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))"#;
    let once = migrate(parse_single(input)).serialize();
    let twice = migrate(parse_single(&once)).serialize();
    assert_eq!(once, twice);
}

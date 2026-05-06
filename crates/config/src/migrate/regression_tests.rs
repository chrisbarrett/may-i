#[cfg(test)]
mod tests {
    use may_i_core::ContextFacts;
    use may_i_core::Keyword;

    use crate::migrate::migrate_forms;

    // ── Eval-equivalence infrastructure ─────────────────────────────────

    /// A test case: command string, args, and runtime facts.
    struct EvalCase {
        cmd: &'static str,
        args: Vec<String>,
        facts: ContextFacts,
    }

    impl EvalCase {
        fn new(cmd: &'static str) -> Self {
            Self {
                cmd,
                args: vec![],
                facts: ContextFacts::default(),
            }
        }

        fn with_args(mut self, args: &[&str]) -> Self {
            self.args = args.iter().map(|s| s.to_string()).collect();
            self
        }

        fn with_fact(mut self, key: &str) -> Self {
            self.facts
                .insert_present(Keyword::new(key).expect("valid keyword"));
            self
        }

        fn with_fact_value(mut self, key: &str, value: &str) -> Self {
            self.facts
                .insert_scalar(Keyword::new(key).expect("valid keyword"), value);
            self
        }
    }

    /// Load a v1 config string through the migration pipeline and return a
    /// parsed, resolved Config ready for evaluation.
    fn load_via_migration(v1_text: &str) -> may_i_core::ast::Config {
        let (cst_nodes, cst_errors) = may_i_sexpr::parse_cst(v1_text);
        assert!(
            cst_errors.is_empty(),
            "v1 config has CST parse errors: {cst_errors:?}"
        );

        let migrated = migrate_forms(cst_nodes);
        let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

        let mut config = crate::parse_config_from_sexprs(&sexprs)
            .unwrap_or_else(|e| panic!("migrated config failed to parse: {e}"));

        let resolved = crate::resolve::validate_and_resolve(&config.rules, &config.defines)
            .unwrap_or_else(|errs| panic!("resolution failed: {}", errs[0].message));
        config.rules = resolved;
        config
    }

    /// Load a v2 (canonical) config string directly.
    fn load_canonical(v2_text: &str) -> may_i_core::ast::Config {
        let mut config = crate::parse_config(v2_text)
            .unwrap_or_else(|e| panic!("canonical config failed to parse: {e}"));

        let resolved = crate::resolve::validate_and_resolve(&config.rules, &config.defines)
            .unwrap_or_else(|errs| panic!("resolution failed: {}", errs[0].message));
        config.rules = resolved;
        config
    }

    /// Evaluate a single case against a config, returning the decision.
    fn eval_decision(config: &may_i_core::ast::Config, case: &EvalCase) -> may_i_core::Decision {
        may_i_engine::evaluate(case.cmd, &case.args, config, &case.facts)
            .expect("evaluation should not fail")
            .decision
    }

    /// Assert that a v1 config, after migration, produces the same evaluation
    /// results as the expected v2 config for all given test cases.
    fn assert_eval_equivalence(v1_text: &str, v2_text: &str, cases: &[EvalCase]) {
        let migrated_config = load_via_migration(v1_text);
        let canonical_config = load_canonical(v2_text);

        for (i, case) in cases.iter().enumerate() {
            let migrated_decision = eval_decision(&migrated_config, case);
            let canonical_decision = eval_decision(&canonical_config, case);
            assert_eq!(
                migrated_decision, canonical_decision,
                "case {i}: cmd={:?} args={:?}\n  v1 migrated → {migrated_decision}\n  canonical  → {canonical_decision}\n  v1: {v1_text}\n  v2: {v2_text}",
                case.cmd, case.args,
            );
        }
    }

    /// Assert structural migration: v1 text migrates to exact v2 text.
    fn assert_migrates_to(v1_text: &str, expected_v2: &str) {
        let (cst_nodes, cst_errors) = may_i_sexpr::parse_cst(v1_text);
        assert!(cst_errors.is_empty(), "CST parse errors: {cst_errors:?}");

        let migrated = migrate_forms(cst_nodes);
        let actual: String = migrated
            .iter()
            .map(|n| n.serialize())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            actual.trim(),
            expected_v2.trim(),
            "migration output mismatch"
        );
    }

    // ── Task 2: Compound form eval-equivalence tests ────────────────────

    #[test]
    fn compound_command_context_args_effect() {
        let v1 = r#"(rule (command "git") (context (has :via/ssh)) (args (positional "push")) (effect :deny "no pushing over ssh"))"#;
        let v2 = r#"(rule "git" (when (fact? :via/ssh) (and (positional "push") (effect :deny "no pushing over ssh"))))"#;

        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("git")
                    .with_args(&["push"])
                    .with_fact(":via/ssh"),
                EvalCase::new("git").with_args(&["push"]),
                EvalCase::new("git")
                    .with_args(&["status"])
                    .with_fact(":via/ssh"),
                EvalCase::new("ls"),
            ],
        );
    }

    #[test]
    fn compound_defcontext_with_and() {
        let v1 = concat!(
            r#"(defcontext rp (and (has :via/ssh) (has [:ssh/host (regex "^prod")])))"#,
            "\n",
            r#"(rule (command "git") (context rp) (effect :ask "production ssh"))"#,
        );
        let v2 = concat!(
            r#"(define rp (and (fact? :via/ssh) (fact? [:ssh/host (regex "^prod")])))"#,
            "\n",
            r#"(rule "git" (when rp (effect :ask "production ssh")))"#,
        );

        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("git")
                    .with_fact(":via/ssh")
                    .with_fact_value(":ssh/host", "prod-web-01"),
                EvalCase::new("git")
                    .with_fact(":via/ssh")
                    .with_fact_value(":ssh/host", "dev-01"),
                EvalCase::new("git").with_fact(":via/ssh"),
                EvalCase::new("git"),
            ],
        );
    }

    #[test]
    fn multi_clause_cond_in_args() {
        let v1 = r#"(rule (command "git") (args (cond ((positional "push") (effect :ask "push")) ((positional "status") (effect :allow "status")) (else (effect :ask "other")))))"#;
        let v2 = r#"(rule "git" (cond ((positional "push") (effect :ask "push")) ((positional "status") (effect :allow "status")) (else (effect :ask "other"))))"#;

        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("git").with_args(&["push"]),
                EvalCase::new("git").with_args(&["status"]),
                EvalCase::new("git").with_args(&["log"]),
                EvalCase::new("ls"),
            ],
        );
    }

    #[test]
    fn named_predicate_ref() {
        let v1 = concat!(
            "(defcontext x (has :via/ssh))\n",
            r#"(rule (command "git") (context x) (effect :allow "ssh ok"))"#,
        );
        let v2 = concat!(
            "(define x (fact? :via/ssh))\n",
            r#"(rule "git" (when x (effect :allow "ssh ok")))"#,
        );

        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("git").with_fact(":via/ssh"),
                EvalCase::new("git"),
            ],
        );
    }

    // ── Task 3: Wrapper migration tests (structural) ────────────────────

    #[test]
    fn wrapper_timeout() {
        let v1 = r#"(wrapper "timeout" (positional (regex "^[0-9]+$") :command+args))"#;
        assert_migrates_to(
            v1,
            r#"(rule "timeout" (positional (regex "^[0-9]+$") . (may-i *)))"#,
        );
    }

    #[test]
    fn wrapper_mise_exec() {
        let v1 = r#"(wrapper "mise" (positional "exec") (flag "--" :command+args))"#;
        assert_migrates_to(v1, r#"(rule "mise" (positional "exec" "--" . (may-i *)))"#);
    }

    #[test]
    fn wrapper_nix_shell_develop() {
        let v1 = r#"(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))"#;
        assert_migrates_to(
            v1,
            r#"(rule "nix" (positional (or "shell" "develop") "--command" . (may-i *)))"#,
        );
    }

    #[test]
    fn wrapper_nix_shell_run() {
        let v1 = r#"(wrapper "nix-shell" (flag "--run" :command+args))"#;
        // The (positional "--run" . R) intermediate now collapses to a
        // structured (parameter "run" R) pattern.
        assert_migrates_to(v1, r#"(rule "nix-shell" (parameter "run" (may-i *)))"#);
    }

    #[test]
    fn wrapper_bash_c() {
        let v1 = r#"(wrapper "bash" (flag "-c" :command+args))"#;
        // The (positional "-c" . R) intermediate now collapses to a
        // structured (parameter "c" R) pattern.
        assert_migrates_to(v1, r#"(rule "bash" (parameter "c" (may-i *)))"#);
    }

    // ── Task 4: has → fact? with complex value patterns ────────────────

    #[test]
    fn has_to_fact_with_regex_value() {
        assert_migrates_to(
            r#"(has [:ssh/host (regex "^prod-")])"#,
            r#"(fact? [:ssh/host (regex "^prod-")])"#,
        );
    }

    #[test]
    fn has_to_fact_with_wildcard_value() {
        assert_migrates_to("(has [:ssh/host *])", "(fact? [:ssh/host *])");
    }

    #[test]
    fn has_to_fact_with_or_value() {
        assert_migrates_to(
            r#"(has [:opencode/agent (or "build" "plan")])"#,
            r#"(fact? [:opencode/agent (or "build" "plan")])"#,
        );
    }

    // ── Task: has with compound value pattern ─────────────────────────

    #[test]
    fn has_with_compound_value_pattern() {
        assert_migrates_to(
            r#"(has [:key (and (regex "^prod-") (not "prod-test"))])"#,
            r#"(fact? [:key (and (regex "^prod-") (not "prod-test"))])"#,
        );
    }

    // ── Task 5: Command patterns inside (command ...) ───────────────────

    #[test]
    fn command_with_or_pattern() {
        let v1 = r#"(rule (command (or "rm" "rmdir")) (effect :deny "reason"))"#;
        let v2 = r#"(rule (or "rm" "rmdir") (effect :deny "reason"))"#;

        assert_migrates_to(v1, v2);
        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("rm"),
                EvalCase::new("rmdir"),
                EvalCase::new("ls"),
            ],
        );
    }

    #[test]
    fn command_with_multi_element_or() {
        let v1 = r#"(rule (command (or "cat" "head" "tail")) (effect :allow "readers"))"#;
        let v2 = r#"(rule (or "cat" "head" "tail") (effect :allow "readers"))"#;

        assert_migrates_to(v1, v2);
        assert_eval_equivalence(
            v1,
            v2,
            &[
                EvalCase::new("cat"),
                EvalCase::new("head"),
                EvalCase::new("tail"),
                EvalCase::new("ls"),
            ],
        );
    }

    #[test]
    fn command_with_regex_pattern() {
        let v1 = r#"(rule (command (regex "^git-")) (effect :allow "reason"))"#;
        assert_migrates_to(v1, r#"(rule (regex "^git-") (effect :allow "reason"))"#);
    }

    // ── Task 6: Comment/trivia preservation ─────────────────────────────

    #[test]
    fn comments_between_top_level_forms() {
        let v1 = concat!(
            ";; First rule\n",
            r#"(rule (command "git") (effect :allow))"#,
            "\n\n",
            ";; Second rule\n",
            r#"(rule (command "ls") (effect :allow))"#,
        );

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(v1);
        assert!(errors.is_empty());

        let migrated = migrate_forms(cst_nodes);
        let output: String = migrated.iter().map(|n| n.serialize()).collect();

        assert!(output.contains(";; First rule"), "first comment lost");
        assert!(output.contains(";; Second rule"), "second comment lost");
    }

    #[test]
    fn multiline_comment_block_above_rule() {
        let v1 = concat!(
            ";; This is a multi-line\n",
            ";; comment block\n",
            r#"(rule (command "git") (effect :allow))"#,
        );

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(v1);
        assert!(errors.is_empty());

        let migrated = migrate_forms(cst_nodes);
        let output: String = migrated.iter().map(|n| n.serialize()).collect();

        assert!(
            output.contains(";; This is a multi-line"),
            "first comment line lost in: {output}"
        );
        assert!(
            output.contains(";; comment block"),
            "second comment line lost in: {output}"
        );
    }

    #[test]
    fn trailing_comment_on_closing_paren() {
        let v1 = "(rule (command \"git\") (effect :allow)) ;; trailing";

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(v1);
        assert!(errors.is_empty());

        let migrated = migrate_forms(cst_nodes);
        let output: String = migrated.iter().map(|n| n.serialize()).collect();

        assert!(
            output.contains(";; trailing"),
            "trailing comment lost in: {output}"
        );
    }

    // ── Task: comments on wrapper forms ─────────────────────────────────

    #[test]
    fn leading_comment_on_wrapper_preserved() {
        let v1 = concat!(
            ";; timeout wrapper\n",
            r#"(wrapper "timeout" (positional (regex "^[0-9]+$") :command+args))"#,
        );

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(v1);
        assert!(errors.is_empty());

        let migrated = migrate_forms(cst_nodes);
        let output: String = migrated.iter().map(|n| n.serialize()).collect();

        assert!(
            output.contains(";; timeout wrapper"),
            "leading comment on wrapper lost in: {output}"
        );
    }

    // ── Task 7: Mixed v1/v2 configs ─────────────────────────────────────

    #[test]
    fn mixed_v1_and_v2_rules() {
        let mixed = concat!(
            r#"(rule "ls" (effect :allow "already v2"))"#,
            "\n",
            r#"(rule (command "git") (effect :deny "v1 form"))"#,
        );

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(mixed);
        assert!(errors.is_empty());

        let migrated = migrate_forms(cst_nodes);
        let output: String = migrated
            .iter()
            .map(|n| n.serialize())
            .collect::<Vec<_>>()
            .join("\n");

        // v2 rule should be unchanged
        assert!(
            output.contains(r#"(rule "ls" (effect :allow "already v2"))"#),
            "v2 rule was modified: {output}"
        );
        // v1 rule should be migrated
        assert!(
            output.contains(r#"(rule "git" (effect :deny "v1 form"))"#),
            "v1 rule not migrated: {output}"
        );

        // Both should evaluate correctly
        let config = load_via_migration(mixed);
        let ls_result = eval_decision(&config, &EvalCase::new("ls"));
        assert_eq!(ls_result, may_i_core::Decision::Allow);

        let git_result = eval_decision(&config, &EvalCase::new("git"));
        assert_eq!(git_result, may_i_core::Decision::Deny);
    }

    #[test]
    fn idempotent_on_canonical_config() {
        let v2 = concat!(
            r#"(rule "git" (effect :allow "ok"))"#,
            "\n",
            r#"(rule "ls" (when (fact? :via/ssh) (effect :ask "ssh")))"#,
        );

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(v2);
        assert!(errors.is_empty());

        let original: String = cst_nodes
            .iter()
            .map(|n| n.serialize())
            .collect::<Vec<_>>()
            .join("\n");

        let migrated = migrate_forms(cst_nodes);
        let after: String = migrated
            .iter()
            .map(|n| n.serialize())
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(
            original, after,
            "canonical config was modified by migration"
        );
    }
}

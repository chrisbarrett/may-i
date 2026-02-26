use super::*;
use super::matcher::*;
use super::visitors::rule_match::match_against_rules;
use may_i_core::{
    ArgMatcher, CaptureKind, CommandMatcher, CondBranch, Config, Effect, Expr, PosExpr, Rule,
    Wrapper, WrapperStep,
};

/// Helper to wrap Expr values in PosExpr::One for tests.
fn pos(exprs: Vec<Expr>) -> Vec<PosExpr> {
    exprs.into_iter().map(PosExpr::One).collect()
}

// ── Helpers ──────────────────────────────────────────────────────

fn empty_config() -> Config {
    Config::default()
}

fn config_with_rules(rules: Vec<Rule>) -> Config {
    Config {
        rules,
        ..Config::default()
    }
}

use may_i_sexpr::Span;

fn test_span() -> Span {
    Span { start: 0, end: 0 }
}

fn allow_rule(cmd: &str) -> Rule {
    Rule {
        command: CommandMatcher::Exact(cmd.to_string()),
        matcher: None,
        effect: Some(Effect { decision: Decision::Allow, reason: Some("allowed".into()) }),
        checks: vec![],
        source_span: test_span(),
    }
}

fn deny_rule(cmd: &str) -> Rule {
    Rule {
        command: CommandMatcher::Exact(cmd.to_string()),
        matcher: None,
        effect: Some(Effect { decision: Decision::Deny, reason: Some("denied".into()) }),
        checks: vec![],
        source_span: test_span(),
    }
}

fn ask_rule(cmd: &str) -> Rule {
    Rule {
        command: CommandMatcher::Exact(cmd.to_string()),
        matcher: None,
        effect: Some(Effect { decision: Decision::Ask, reason: Some("ask".into()) }),
        checks: vec![],
        source_span: test_span(),
    }
}

/// Build a VarEnv with specific variables for testing.
fn env_with(vars: &[(&str, VarState)]) -> VarEnv {
    let mut env = VarEnv::empty();
    for (name, state) in vars {
        env.set(name.to_string(), state.clone());
    }
    env
}

// ── Flag expansion ──────────────────────────────────────────────

#[test]
fn test_flag_expansion() {
    let args = vec![Word::literal("-abc"), Word::literal("--verbose")];
    let expanded = expand_flags(&args);
    assert_eq!(
        expanded,
        vec![
            ResolvedArg::Literal("-a".into()),
            ResolvedArg::Literal("-b".into()),
            ResolvedArg::Literal("-c".into()),
            ResolvedArg::Literal("--verbose".into()),
        ]
    );
}

#[test]
fn flag_expansion_single_short_flag_unchanged() {
    let args = vec![Word::literal("-v")];
    let expanded = expand_flags(&args);
    assert_eq!(expanded, vec![ResolvedArg::Literal("-v".into())]);
}

#[test]
fn flag_expansion_plain_args_unchanged() {
    let args = vec![Word::literal("hello"), Word::literal("world")];
    let expanded = expand_flags(&args);
    assert_eq!(
        expanded,
        vec![
            ResolvedArg::Literal("hello".into()),
            ResolvedArg::Literal("world".into()),
        ]
    );
}

#[test]
fn flag_expansion_long_flag_unchanged() {
    let args = vec![Word::literal("--verbose")];
    let expanded = expand_flags(&args);
    assert_eq!(expanded, vec![ResolvedArg::Literal("--verbose".into())]);
}

// ── Decision::most_restrictive ──────────────────────────────────

#[test]
fn test_decision_most_restrictive() {
    assert_eq!(Decision::Allow.most_restrictive(Decision::Ask), Decision::Ask);
    assert_eq!(Decision::Ask.most_restrictive(Decision::Deny), Decision::Deny);
    assert_eq!(Decision::Allow.most_restrictive(Decision::Allow), Decision::Allow);
}

#[test]
fn most_restrictive_deny_always_wins() {
    assert_eq!(Decision::Deny.most_restrictive(Decision::Allow), Decision::Deny);
    assert_eq!(Decision::Deny.most_restrictive(Decision::Ask), Decision::Deny);
    assert_eq!(Decision::Deny.most_restrictive(Decision::Deny), Decision::Deny);
}

// ── evaluate(): simple commands ─────────────────────────────────

#[test]
fn evaluate_simple_command_allowed() {
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate("ls", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_simple_command_denied() {
    let config = config_with_rules(vec![deny_rule("rm")]);
    let result = evaluate("rm -rf /", &config);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn evaluate_no_matching_rule_asks() {
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate("whoami", &config);
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(
        result.reason.as_deref(),
        Some("No rule for command `whoami`")
    );
}

#[test]
fn evaluate_empty_input_allows() {
    // Empty input means no command to evaluate — nothing to block.
    let config = empty_config();
    let result = evaluate("", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── evaluate(): pipelines ───────────────────────────────────────

#[test]
fn evaluate_pipeline_all_allowed() {
    let config = config_with_rules(vec![allow_rule("ls"), allow_rule("grep")]);
    let result = evaluate("ls | grep foo", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_pipeline_one_denied() {
    let config = config_with_rules(vec![allow_rule("ls"), deny_rule("rm")]);
    let result = evaluate("ls | rm", &config);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn evaluate_pipeline_most_restrictive_wins() {
    let config = config_with_rules(vec![allow_rule("cat"), ask_rule("sort")]);
    let result = evaluate("cat file | sort", &config);
    assert_eq!(result.decision, Decision::Ask);
}

// ── evaluate(): sequences ───────────────────────────────────────

#[test]
fn evaluate_sequence_all_allowed() {
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate("echo hi; ls", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_sequence_one_denied() {
    let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
    let result = evaluate("echo hi; rm file", &config);
    assert_eq!(result.decision, Decision::Deny);
}

// ── evaluate(): and/or ──────────────────────────────────────────

#[test]
fn evaluate_and_chain() {
    let config = config_with_rules(vec![allow_rule("mkdir"), allow_rule("cd")]);
    let result = evaluate("mkdir foo && cd foo", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_or_chain_denied() {
    let config = config_with_rules(vec![allow_rule("ls"), deny_rule("rm")]);
    let result = evaluate("ls || rm", &config);
    assert_eq!(result.decision, Decision::Deny);
}

// ── evaluate(): compound commands ───────────────────────────────

#[test]
fn evaluate_if_command() {
    let config = config_with_rules(vec![allow_rule("test"), allow_rule("echo")]);
    let result = evaluate("if test -f foo; then echo found; fi", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_for_loop_with_literal_words() {
    // NEW: for loops with literal words now enumerate iterations
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("for x in a b c; do echo $x; done", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_while_loop() {
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate("while true; do echo loop; done", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── command_matches() ───────────────────────────────────────────

#[test]
fn command_matches_exact() {
    assert!(command_matches("git", &CommandMatcher::Exact("git".into())));
    assert!(!command_matches("gitx", &CommandMatcher::Exact("git".into())));
}

#[test]
fn command_matches_regex() {
    let re = regex::Regex::new("^(git|hg)$").unwrap();
    assert!(command_matches("git", &CommandMatcher::Regex(re.clone())));
    assert!(command_matches("hg", &CommandMatcher::Regex(re.clone())));
    assert!(!command_matches("svn", &CommandMatcher::Regex(re)));
}

#[test]
fn command_matches_list() {
    let list = CommandMatcher::List(vec!["cat".into(), "bat".into(), "less".into()]);
    assert!(command_matches("cat", &list));
    assert!(command_matches("bat", &list));
    assert!(!command_matches("more", &list));
}

// ── ArgMatcher::Positional ──────────────────────────────────────

#[test]
fn positional_matcher_literal() {
    let matcher = ArgMatcher::Positional(pos(vec![Expr::Literal("status".into())]));
    let args = vec![ResolvedArg::Literal("status".into())];
    assert!(matcher_matches(&matcher, &args));
}

#[test]
fn positional_matcher_wildcard() {
    let matcher = ArgMatcher::Positional(pos(vec![Expr::Wildcard]));
    let args = vec![ResolvedArg::Literal("anything".into())];
    assert!(matcher_matches(&matcher, &args));
}

#[test]
fn positional_matcher_regex() {
    let matcher = ArgMatcher::Positional(pos(vec![Expr::Regex(regex::Regex::new("^(status|log)$").unwrap())]));
    assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("status".into())]));
    assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("log".into())]));
    assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("push".into())]));
}

#[test]
fn positional_matcher_too_few_args() {
    let matcher = ArgMatcher::Positional(pos(vec![
        Expr::Literal("a".into()),
        Expr::Literal("b".into()),
    ]));
    assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("a".into())]));
}

#[test]
fn positional_matcher_skips_flags() {
    let matcher = ArgMatcher::Positional(pos(vec![Expr::Literal("status".into())]));
    let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
    assert!(matcher_matches(&matcher, &args));
}

// ── ArgMatcher::ExactPositional ──────────────────────────────────

#[test]
fn exact_positional_matches_exact_count() {
    let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
    assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("status".into())]));
}

#[test]
fn exact_positional_rejects_extra_args() {
    let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("remote".into())]));
    assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("remote".into()), ResolvedArg::Literal("add".into())]));
}

#[test]
fn exact_positional_rejects_too_few() {
    let matcher = ArgMatcher::ExactPositional(pos(vec![
        Expr::Literal("a".into()),
        Expr::Literal("b".into()),
    ]));
    assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("a".into())]));
}

#[test]
fn exact_positional_skips_flags() {
    let matcher = ArgMatcher::ExactPositional(pos(vec![Expr::Literal("status".into())]));
    let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
    assert!(matcher_matches(&matcher, &args));
}

// ── ArgMatcher::Anywhere ────────────────────────────────────────

#[test]
fn anywhere_matcher_present() {
    let tokens = vec![Expr::Literal("--force".into())];
    let matcher = ArgMatcher::Anywhere(tokens);
    let args = vec![ResolvedArg::Literal("push".into()), ResolvedArg::Literal("--force".into())];
    assert!(matcher_matches(&matcher, &args));
}

#[test]
fn anywhere_matcher_absent() {
    let tokens = vec![Expr::Literal("--force".into())];
    let matcher = ArgMatcher::Anywhere(tokens);
    let args = vec![ResolvedArg::Literal("push".into()), ResolvedArg::Literal("origin".into())];
    assert!(!matcher_matches(&matcher, &args));
}

#[test]
fn anywhere_matcher_or_semantics() {
    let tokens = vec![
        Expr::Literal("--force".into()),
        Expr::Literal("-f".into()),
    ];
    let matcher = ArgMatcher::Anywhere(tokens);
    assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("-f".into())]));
    assert!(matcher_matches(&matcher, &[ResolvedArg::Literal("--force".into())]));
    assert!(!matcher_matches(&matcher, &[ResolvedArg::Literal("--verbose".into())]));
}

// ── And/Or/Not matchers ──────────────────────────────────────────

#[test]
fn and_matcher_all_must_pass() {
    let m = ArgMatcher::And(vec![
        ArgMatcher::Positional(pos(vec![Expr::Literal("push".into())])),
        ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
            Expr::Literal("--force".into()),
        ]))),
    ]);
    assert!(matcher_matches(&m, &[ResolvedArg::Literal("push".into()), ResolvedArg::Literal("origin".into())]));
    assert!(!matcher_matches(&m, &[ResolvedArg::Literal("push".into()), ResolvedArg::Literal("--force".into())]));
}

#[test]
fn or_matcher_any_must_pass() {
    let m = ArgMatcher::Or(vec![
        ArgMatcher::Anywhere(vec![Expr::Literal("-v".into())]),
        ArgMatcher::Anywhere(vec![Expr::Literal("--verbose".into())]),
    ]);
    assert!(matcher_matches(&m, &[ResolvedArg::Literal("-v".into())]));
    assert!(matcher_matches(&m, &[ResolvedArg::Literal("--verbose".into())]));
    assert!(!matcher_matches(&m, &[ResolvedArg::Literal("--quiet".into())]));
}

#[test]
fn not_matcher_inverts() {
    let m = ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
        Expr::Literal("--force".into()),
    ])));
    assert!(matcher_matches(&m, &[ResolvedArg::Literal("push".into())]));
    assert!(!matcher_matches(&m, &[ResolvedArg::Literal("--force".into())]));
}

// ── extract_positional_args() ───────────────────────────────────

#[test]
fn extract_positional_skips_short_flags() {
    let args = vec![ResolvedArg::Literal("-v".into()), ResolvedArg::Literal("status".into())];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![ResolvedArg::Literal("status".into())]);
}

#[test]
fn extract_positional_skips_long_flags_and_values() {
    let args = vec![
        ResolvedArg::Literal("--output".into()),
        ResolvedArg::Literal("file.txt".into()),
        ResolvedArg::Literal("input.txt".into()),
    ];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![ResolvedArg::Literal("input.txt".into())]);
}

#[test]
fn extract_positional_long_flag_with_equals() {
    let args = vec![
        ResolvedArg::Literal("--output=file.txt".into()),
        ResolvedArg::Literal("input.txt".into()),
    ];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![ResolvedArg::Literal("input.txt".into())]);
}

#[test]
fn extract_positional_bare_dash_is_positional() {
    let args = vec![ResolvedArg::Literal("-".into())];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![ResolvedArg::Literal("-".into())]);
}

#[test]
fn extract_positional_double_dash_is_positional() {
    let args = vec![
        ResolvedArg::Literal("run".into()),
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("test".into()),
    ];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![
        ResolvedArg::Literal("run".into()),
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("test".into()),
    ]);
}

#[test]
fn extract_positional_double_dash_terminates_flags() {
    let args = vec![
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("--force".into()),
        ResolvedArg::Literal("-v".into()),
    ];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("--force".into()),
        ResolvedArg::Literal("-v".into()),
    ]);
}

#[test]
fn extract_positional_flags_before_double_dash_skipped() {
    let args = vec![
        ResolvedArg::Literal("-v".into()),
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("arg".into()),
    ];
    let pos = extract_positional_args(&args);
    assert_eq!(pos, vec![
        ResolvedArg::Literal("--".into()),
        ResolvedArg::Literal("arg".into()),
    ]);
}

// ── Rule matching integration ───────────────────────────────────

#[test]
fn rule_with_positional_matcher() {
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::Positional(pos(vec![
            Expr::Literal("status".into()),
        ]))),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate("git status", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn rule_with_positional_no_match() {
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::Positional(pos(vec![
            Expr::Literal("status".into()),
        ]))),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate("git push", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn deny_rule_wins_over_allow() {
    let rules = vec![
        allow_rule("rm"),
        Rule {
            command: CommandMatcher::Exact("rm".into()),
            matcher: Some(ArgMatcher::Anywhere(vec![
                Expr::Literal("-r".into()),
            ])),
            effect: Some(Effect { decision: Decision::Deny, reason: Some("dangerous".into()) }),
            checks: vec![],
            source_span: test_span(),
        },
    ];
    let config = config_with_rules(rules);
    let result = evaluate("rm -rf /", &config);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn first_matching_non_deny_rule_wins() {
    let rules = vec![
        Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Ask, reason: Some("first".into()) }),
            checks: vec![],
            source_span: test_span(),
        },
        Rule {
            command: CommandMatcher::Exact("git".into()),
            matcher: None,
            effect: Some(Effect { decision: Decision::Allow, reason: Some("second".into()) }),
            checks: vec![],
            source_span: test_span(),
        },
    ];
    let config = config_with_rules(rules);
    let result = evaluate("git status", &config);
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(result.reason.as_deref(), Some("first"));
}

#[test]
fn regex_command_matcher_in_rule() {
    let rule = Rule {
        command: CommandMatcher::Regex(regex::Regex::new("^(cat|bat|less)$").unwrap()),
        matcher: None,
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    assert_eq!(evaluate("cat file", &config).decision, Decision::Allow);
    assert_eq!(evaluate("bat file", &config).decision, Decision::Allow);
    assert_eq!(evaluate("less file", &config).decision, Decision::Allow);
    assert_eq!(evaluate("more file", &config).decision, Decision::Ask);
}

#[test]
fn list_command_matcher_in_rule() {
    let rule = Rule {
        command: CommandMatcher::List(vec!["cat".into(), "bat".into()]),
        matcher: None,
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    assert_eq!(evaluate("cat file", &config).decision, Decision::Allow);
    assert_eq!(evaluate("bat file", &config).decision, Decision::Allow);
    assert_eq!(evaluate("head file", &config).decision, Decision::Ask);
}

// ── Wrapper unwrapping ──────────────────────────────────────────

fn after_flags_wrapper(command: &str) -> Wrapper {
    Wrapper {
        command: command.into(),
        steps: vec![WrapperStep::Positional {
            patterns: vec![],
            capture: Some(CaptureKind::CommandArgs),
        }],
    }
}

fn after_delimiter_wrapper(command: &str, delim: &str) -> Wrapper {
    Wrapper {
        command: command.into(),
        steps: vec![WrapperStep::Flag {
            name: delim.into(),
            capture: CaptureKind::CommandArgs,
        }],
    }
}

#[test]
fn wrapper_after_flags_unwraps() {
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![after_flags_wrapper("sudo")],
        ..Config::default()
    };
    let result = evaluate("sudo ls", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn wrapper_after_flags_with_flags() {
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![after_flags_wrapper("sudo")],
        ..Config::default()
    };
    let result = evaluate("sudo -u ls", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn wrapper_after_delimiter_unwraps() {
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![after_delimiter_wrapper("env", "--")],
        ..Config::default()
    };
    let result = evaluate("env FOO=bar -- ls -la", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn wrapper_with_positional_args() {
    // (wrapper "docker" (positional "exec" :command+args))
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![Wrapper {
            command: "docker".into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![Expr::Literal("exec".into())],
                capture: Some(CaptureKind::CommandArgs),
            }],
        }],
        ..Config::default()
    };
    let result = evaluate("docker exec container ls", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn wrapper_positional_mismatch_no_unwrap() {
    let config = Config {
        rules: vec![allow_rule("docker")],
        wrappers: vec![Wrapper {
            command: "docker".into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![Expr::Literal("exec".into())],
                capture: Some(CaptureKind::CommandArgs),
            }],
        }],
        ..Config::default()
    };
    let result = evaluate("docker run container", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn wrapper_not_matching_command() {
    let config = Config {
        rules: vec![allow_rule("nohup")],
        wrappers: vec![after_flags_wrapper("sudo")],
        ..Config::default()
    };
    let result = evaluate("nohup sleep 10", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn wrapper_ssh_skips_hostname() {
    // (wrapper "ssh" (positional * :command+args))
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![Wrapper {
            command: "ssh".into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![Expr::Wildcard],
                capture: Some(CaptureKind::CommandArgs),
            }],
        }],
        ..Config::default()
    };
    assert_eq!(evaluate("ssh host ls", &config).decision, Decision::Allow);
    assert_eq!(evaluate("ssh -v host ls", &config).decision, Decision::Allow);
}

#[test]
fn wrapper_ssh_no_inner_command() {
    // ssh without a trailing command should not unwrap
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![Wrapper {
            command: "ssh".into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![Expr::Wildcard],
                capture: Some(CaptureKind::CommandArgs),
            }],
        }],
        ..Config::default()
    };
    // Falls back to evaluating "ssh" itself (not allowed → ask)
    assert_eq!(evaluate("ssh host", &config).decision, Decision::Ask);
}

#[test]
fn wrapper_nix_shell_flag_command() {
    // (wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![Wrapper {
            command: "nix".into(),
            steps: vec![
                WrapperStep::Positional {
                    patterns: vec![Expr::Or(vec![
                        Expr::Literal("shell".into()),
                        Expr::Literal("develop".into()),
                    ])],
                    capture: None,
                },
                WrapperStep::Flag {
                    name: "--command".into(),
                    capture: CaptureKind::CommandArgs,
                },
            ],
        }],
        ..Config::default()
    };
    assert_eq!(
        evaluate("nix shell --command ls", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("nix develop --command ls", &config).decision,
        Decision::Allow
    );
    // Wrong subcommand — wrapper doesn't apply, falls through to rule eval
    assert_eq!(
        evaluate("nix run --command ls", &config).decision,
        Decision::Ask
    );
}

#[test]
fn wrapper_mise_validate_then_delimiter() {
    // (wrapper "mise" (positional "exec") (flag "--" :command+args))
    let config = Config {
        rules: vec![allow_rule("ls")],
        wrappers: vec![Wrapper {
            command: "mise".into(),
            steps: vec![
                WrapperStep::Positional {
                    patterns: vec![Expr::Literal("exec".into())],
                    capture: None,
                },
                WrapperStep::Flag {
                    name: "--".into(),
                    capture: CaptureKind::CommandArgs,
                },
            ],
        }],
        ..Config::default()
    };
    assert_eq!(
        evaluate("mise exec -- ls -la", &config).decision,
        Decision::Allow
    );
    // Wrong subcommand — wrapper doesn't apply
    assert_eq!(
        evaluate("mise run -- ls", &config).decision,
        Decision::Ask
    );
}

// ── Dynamic parts ────────────────────────────────────────────────

#[test]
fn dynamic_parts_in_command_asks() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("echo $(whoami)", &config);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("echo"), "should mention the command: {reason}");
    assert!(reason.contains("$(whoami)"), "should mention the dynamic part: {reason}");
}

#[test]
fn normal_file_allowed() {
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate("cat README.md", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── match_against_rules(): edge cases ──────────────────────────

#[test]
fn evaluate_empty_command_name() {
    let sc = SimpleCommand {
        assignments: vec![],
        words: vec![],
        redirections: vec![],
    };
    let result = match_against_rules(&sc, &empty_config());
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(result.reason.as_deref(), Some("Unknown command"));
}

// ── Not+Anywhere (forbidden) with rule integration ─────────────

#[test]
fn not_anywhere_denies_with_forbidden_flag() {
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::And(vec![
            ArgMatcher::Positional(pos(vec![Expr::Literal("push".into())])),
            ArgMatcher::Not(Box::new(ArgMatcher::Anywhere(vec![
                Expr::Literal("--force".into()),
                Expr::Literal("-f".into()),
            ]))),
        ])),
        effect: Some(Effect { decision: Decision::Allow, reason: Some("safe push".into()) }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);

    assert_eq!(
        evaluate("git push origin main", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("git push --force origin main", &config).decision,
        Decision::Ask
    );
}

// ── Anywhere matcher with regex pattern ─────────────────────────

#[test]
fn anywhere_matcher_regex_pattern() {
    let rule = Rule {
        command: CommandMatcher::Exact("grep".into()),
        matcher: Some(ArgMatcher::Anywhere(vec![
            Expr::Regex(regex::Regex::new("^-r$").unwrap()),
        ])),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    assert_eq!(
        evaluate("grep -r pattern .", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("grep pattern .", &config).decision,
        Decision::Ask
    );
}

// ── Default decision when no rules ──────────────────────────────

#[test]
fn no_rules_defaults_to_ask() {
    let config = empty_config();
    let result = evaluate("ls", &config);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Subshell and brace group evaluation ─────────────────────────

#[test]
fn evaluate_subshell() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("(echo hello)", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn evaluate_brace_group() {
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate("{ echo hi; ls; }", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Environment variable resolution ──────────────────────────────

#[test]
fn env_var_resolved_allows_static_analysis() {
    let env = env_with(&[("TEST_MAYI_HOME", VarState::Safe(Some("/home/user".into())))]);
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate_with_env("echo $TEST_MAYI_HOME && ls", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn unresolved_env_var_triggers_ask() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate_with_env("echo $HOME && ls", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("echo"), "should mention the command: {reason}");
    assert!(reason.contains("$HOME"), "should mention the variable: {reason}");
}

#[test]
fn command_sub_never_resolvable() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate_with_env("echo $(whoami) && ls", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("echo"), "should mention the command: {reason}");
    assert!(reason.contains("$(whoami)"), "should mention command substitution: {reason}");
}

#[test]
fn deny_wins_with_resolved_env_var() {
    let env = env_with(&[("TEST_MAYI_HOME3", VarState::Safe(Some("/tmp".into())))]);
    let config = config_with_rules(vec![deny_rule("ls"), allow_rule("echo")]);
    let result = evaluate_with_env("ls && echo $TEST_MAYI_HOME3", &config, &env);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn for_loop_dynamic_iteration_words_ask() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("for f in $items; do echo $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("$items"), "should mention the variable: {reason}");
}

// ── Parameter expansion operator integration ─────────────────────

#[test]
fn param_op_resolved_safe_env_allows() {
    let env = env_with(&[("TEST_MAYI_PATH", VarState::Safe(Some("/usr/local/bin".into())))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo ${TEST_MAYI_PATH##*/}", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn param_op_unresolved_triggers_ask() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo ${UNKNOWN_VAR#pat}", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("UNKNOWN_VAR"), "should mention the variable: {reason}");
}

#[test]
fn param_op_default_value_with_safe_env() {
    let env = env_with(&[("TEST_MAYI_OPT", VarState::Safe(Some("value".into())))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo ${TEST_MAYI_OPT:-fallback}", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn param_op_in_double_quotes_resolved() {
    let env = env_with(&[("TEST_MAYI_FILE", VarState::Safe(Some("archive.tar.gz".into())))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"echo "${TEST_MAYI_FILE%%.*}""#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Dynamic parts in assignment values ───────────────────────────

#[test]
fn dynamic_in_assignment_value_triggers_ask() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("FOO=$(whoami) echo hello", &config);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Dynamic parts in redirect targets ────────────────────────────

#[test]
fn dynamic_in_redirect_target_triggers_ask() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo hello > $OUTFILE", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Blocked path removal verification ─────────────────────────────

#[test]
fn cat_env_allowed_with_rule() {
    // After blocked-path removal, cat .env is allowed if cat has an allow rule
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate("cat .env", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn cat_ssh_allowed_with_rule() {
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate("cat .ssh/id_rsa", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Variable assignment resolution ────────────────────────────────

#[test]
fn literal_assignment_resolution() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x="hello"; echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn path_assignment_and_cat() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate_with_env(r#"x="/tmp"; cat $x/file"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn transitive_assignment_resolution() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x="a"; y=$x; echo $y"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn reassignment_resolution() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x="a"; x="b"; echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn resolution_in_first_of_and() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo"), allow_rule("ls")]);
    let result = evaluate_with_env(r#"x="hello"; echo $x && ls"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Unresolved variables ─────────────────────────────────────────

#[test]
fn unknown_variable_asks() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo $UNKNOWN", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn assigned_from_unsafe_asks() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("x=$UNKNOWN; echo $x", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn transitive_unsafety() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("x=$UNKNOWN; y=$x; echo $y", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Environment variable integration ─────────────────────────────

#[test]
fn env_var_resolves() {
    let env = env_with(&[("HOME", VarState::Safe(Some("/home/user".into())))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo $HOME", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn local_assignment_overrides_env() {
    let env = env_with(&[("HOME", VarState::Safe(Some("/home/user".into())))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("HOME=/override; echo $HOME", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn nonexistent_env_var_asks() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo $NOEXIST", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── If/else branching ────────────────────────────────────────────

#[test]
fn if_both_branches_safe_is_unresolvable() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    // Both branches assign safe values, so x is safe (but opaque) after
    let result = evaluate_with_env(
        r#"if true; then x="a"; else x="b"; fi; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn if_only_then_assigns_and_var_was_unknown() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    // Only then-branch assigns; x was unknown before → unsafe after
    let result = evaluate_with_env(
        r#"if true; then x="a"; fi; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn if_one_branch_unsafe() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate_with_env(
        r#"if true; then x="a"; else x=$UNKNOWN; fi; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn if_elif_else_all_safe() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate_with_env(
        r#"if true; then x="a"; elif true; then x="b"; else x="c"; fi; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Allow);
}

// ── For-loop enumeration ─────────────────────────────────────────

#[test]
fn for_loop_literal_words_enumerates() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("for f in a b c; do echo $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn for_loop_literal_words_cat() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate_with_env("for f in a b c; do cat $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn for_loop_deny_wins_across_iterations() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![deny_rule("rm")]);
    let result = evaluate_with_env("for f in a b c; do rm $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn for_loop_ask_for_unknown_cmd() {
    let env = VarEnv::empty();
    let config = empty_config();
    let result = evaluate_with_env("for f in a b c; do unknown_cmd $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn for_loop_nested() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(
        "for x in a b; do for y in c d; do echo $x $y; done; done",
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Allow);
}

// ── For-loop with non-literal words ──────────────────────────────

#[test]
fn for_loop_glob_words_opaque() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("for f in *.txt; do echo $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn for_loop_glob_cat_no_constraints() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("cat")]);
    let result = evaluate_with_env("for f in *.txt; do cat $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn for_loop_unsafe_items_ask() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("for f in $items; do echo $f; done", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Opaque-arg rule matching ─────────────────────────────────────

#[test]
fn opaque_arg_with_no_constraints_allows() {
    // echo with allow rule and no arg constraints → Allow
    let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo $safe_opaque", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn opaque_first_positional_no_match() {
    // git $safe_opaque with (positional "push" *) → does not match
    let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("push".into())),
            PosExpr::One(Expr::Wildcard),
        ])),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate_with_env("git $safe_opaque", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn opaque_second_positional_wildcard_matches() {
    // git push $safe_opaque with (positional "push" *) → Allow
    let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("push".into())),
            PosExpr::One(Expr::Wildcard),
        ])),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate_with_env("git push $safe_opaque", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn opaque_second_positional_literal_no_match() {
    // git push $safe_opaque with (positional "push" "origin") → Ask
    let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
    let rule = Rule {
        command: CommandMatcher::Exact("git".into()),
        matcher: Some(ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("push".into())),
            PosExpr::One(Expr::Literal("origin".into())),
        ])),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate_with_env("git push $safe_opaque", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn opaque_arg_anywhere_no_match() {
    // cmd $safe_opaque with (anywhere "--force") → opaque doesn't match
    let env = env_with(&[("safe_opaque", VarState::Safe(None))]);
    let rule = Rule {
        command: CommandMatcher::Exact("cmd".into()),
        matcher: Some(ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())])),
        effect: Some(Effect { decision: Decision::Allow, reason: None }),
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate_with_env("cmd $safe_opaque", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Sequential scope ─────────────────────────────────────────────

#[test]
fn assignment_before_use_resolves() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x="a" && echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn use_before_assignment_asks() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("echo $x; x=\"a\"", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

// ── Cond rule body ───────────────────────────────────────────────

#[test]
fn cond_first_branch_matches() {
    let rule = Rule {
        command: CommandMatcher::Exact("tmux".into()),
        matcher: Some(ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(pos(vec![
                    Expr::Literal("source-file".into()),
                ]))),
                effect: Effect { decision: Decision::Allow, reason: Some("config reload".into()) },
            },
            CondBranch {
                matcher: None,
                effect: Effect { decision: Decision::Deny, reason: Some("unknown".into()) },
            },
        ])),
        effect: None,
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate("tmux source-file foo.conf", &config);
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason.as_deref(), Some("config reload"));
}

#[test]
fn cond_fallthrough_to_wildcard() {
    let rule = Rule {
        command: CommandMatcher::Exact("tmux".into()),
        matcher: Some(ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(pos(vec![
                    Expr::Literal("source-file".into()),
                ]))),
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            CondBranch {
                matcher: None,
                effect: Effect { decision: Decision::Deny, reason: Some("fallback deny".into()) },
            },
        ])),
        effect: None,
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate("tmux kill-session", &config);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.reason.as_deref(), Some("fallback deny"));
}

#[test]
fn cond_no_wildcard_no_match_skips_rule() {
    let rule = Rule {
        command: CommandMatcher::Exact("tmux".into()),
        matcher: Some(ArgMatcher::Cond(vec![CondBranch {
            matcher: Some(ArgMatcher::Positional(pos(vec![
                Expr::Literal("source-file".into()),
            ]))),
            effect: Effect { decision: Decision::Allow, reason: None },
        }])),
        effect: None,
        checks: vec![],
        source_span: test_span(),
    };
    let config = config_with_rules(vec![rule]);
    let result = evaluate("tmux kill-session", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn cond_deny_branch_wins_across_rules() {
    let rules = vec![
        Rule {
            command: CommandMatcher::Exact("tmux".into()),
            matcher: Some(ArgMatcher::Cond(vec![
                CondBranch {
                    matcher: Some(ArgMatcher::Positional(pos(vec![
                        Expr::Literal("source-file".into()),
                    ]))),
                    effect: Effect { decision: Decision::Allow, reason: None },
                },
                CondBranch {
                    matcher: None,
                    effect: Effect { decision: Decision::Deny, reason: Some("blocked".into()) },
                },
            ])),
            effect: None,
            checks: vec![],
            source_span: test_span(),
        },
        allow_rule("tmux"),
    ];
    let config = config_with_rules(rules);
    let result = evaluate("tmux kill-session", &config);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn cond_integration_tmux_use_case() {
    use may_i_config::parse as config_parse;

    let config = config_parse::parse(
        r#"
        (rule (command "tmux")
              (args (cond
                ((positional "source-file" (or "~/.config/tmux/custom.conf"
                                               "~/.config/tmux/tmux.conf"))
                 (effect :allow "Reloading config is safe"))
                (else
                 (effect :deny "Unknown tmux source-file"))))
              (check :allow "tmux source-file ~/.config/tmux/custom.conf"
                     :deny "tmux source-file /tmp/evil.conf"))
        "#,
        "<test>",
    )
    .unwrap();

    assert_eq!(
        evaluate("tmux source-file ~/.config/tmux/custom.conf", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("tmux source-file ~/.config/tmux/tmux.conf", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("tmux source-file /tmp/evil.conf", &config).decision,
        Decision::Deny
    );
    assert_eq!(
        evaluate("tmux kill-session", &config).decision,
        Decision::Deny
    );

    let results = crate::check::run_checks(&config);
    assert!(results.iter().all(|r| r.passed), "checks should pass: {results:?}");
}

// ── Expr::Cond as implicit rule effect ──────────────────────────

#[test]
fn expr_cond_in_positional_matching_branch() {
    use may_i_config::parse as config_parse;

    let config = config_parse::parse(
        r#"(rule (command "tmux")
               (args (positional "source-file"
                                 (if (or "~/.config/tmux/custom.conf"
                                         "~/.config/tmux/tmux.conf")
                                     (effect :allow "safe config")
                                     (effect :deny "unknown file")))))"#,
        "<test>",
    )
    .unwrap();

    assert_eq!(
        evaluate("tmux source-file ~/.config/tmux/custom.conf", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("tmux source-file ~/.config/tmux/tmux.conf", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("tmux source-file /tmp/evil.conf", &config).decision,
        Decision::Deny
    );
}

#[test]
fn expr_cond_in_positional_no_match_skips_rule() {
    use may_i_config::parse as config_parse;

    let config = config_parse::parse(
        r#"(rule (command "tmux")
               (args (positional "source-file"
                                 (when "safe.conf"
                                       (effect :allow "safe")))))"#,
        "<test>",
    )
    .unwrap();

    assert_eq!(
        evaluate("tmux source-file safe.conf", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("tmux source-file other.conf", &config).decision,
        Decision::Ask
    );
    assert_eq!(
        evaluate("tmux kill-session", &config).decision,
        Decision::Ask
    );
}

#[test]
fn expr_cond_in_anywhere() {
    use may_i_config::parse as config_parse;

    let config = config_parse::parse(
        r#"(rule (command "foo")
               (args (anywhere (if "--safe"
                                   (effect :allow "safe flag")
                                   (effect :deny "unsafe")))))"#,
        "<test>",
    )
    .unwrap();

    assert_eq!(
        evaluate("foo --safe", &config).decision,
        Decision::Allow
    );
    assert_eq!(
        evaluate("foo --other", &config).decision,
        Decision::Deny
    );
}

// ── OneOrMore break path in match_positional ─────────────────────

#[test]
fn one_or_more_stops_on_mismatch() {
    use may_i_config::parse as config_parse;

    let config = config_parse::parse(
        r#"(rule (command "cmd")
              (args (exact (+ "a") "b"))
              (effect :allow))"#,
        "<test>",
    )
    .unwrap();

    assert_eq!(evaluate("cmd a a b", &config).decision, Decision::Allow);
    assert_eq!(evaluate("cmd a b", &config).decision, Decision::Allow);
    assert_eq!(evaluate("cmd b", &config).decision, Decision::Ask);
    assert_eq!(evaluate("cmd a b extra", &config).decision, Decision::Ask);
}

// ── Subshell isolation ─────────────────────────────────────────

#[test]
fn subshell_does_not_affect_outer_scope() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    // x="safe"; (x="tainted"); echo $x → x is still "safe" outside subshell
    // But we start with empty env, so x is set by the first assignment
    let result = evaluate_with_env(
        r#"x="safe"; (x="tainted"); echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Allow);
}

// ── Empty simple commands → Ask ──────────────────────────────────

#[test]
fn compound_with_no_simple_commands_asks() {
    let config = config_with_rules(vec![allow_rule("f")]);
    let result = evaluate("f() { :; }", &config);
    let result2 = evaluate("()", &config);
    assert!(result.decision == Decision::Allow || result.decision == Decision::Ask);
    assert!(result2.decision == Decision::Ask || result2.decision == Decision::Allow);
}

// ── Command substitution safety ─────────────────────────────────

#[test]
fn cmd_sub_allowed_inner_makes_var_safe_opaque() {
    // x=$(echo hello); echo $x → Allow (echo is allowed, x is safe+opaque)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x=$(echo hello); echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn cmd_sub_ask_inner_makes_var_unsafe() {
    // x=$(dangerous_cmd); echo $x → Ask (inner is Ask → x unsafe)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("x=$(dangerous_cmd); echo $x", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn cmd_sub_opaque_used_as_command_name_asks() {
    // x=$(echo hello); $x → Ask (x opaque, used as command name)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("x=$(echo hello); $x", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn cmd_sub_in_inline_assignment_allowed() {
    // FOO=$(echo hello) echo $FOO → Allow (echo allowed → FOO safe+opaque)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("FOO=$(echo hello) echo $FOO", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn cmd_sub_in_double_quotes_resolved() {
    // x="$(echo hello)"; echo $x → Allow
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"x="$(echo hello)"; echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn backtick_sub_allowed_inner_makes_var_safe() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("x=`echo hello`; echo $x", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

// ── While/until loop variable tainting ───────────────────────────

#[test]
fn while_safe_body_preserves_safety() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate_with_env(
        r#"x="safe"; while true; do x="still safe"; done; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn while_tainting_body_makes_unsafe() {
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate_with_env(
        "x=\"safe\"; while true; do x=$UNKNOWN; done; echo $x",
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn while_assigns_new_var_is_unsafe_after() {
    // while true; do x="a"; done; echo $x → Ask (x may not be assigned)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("true"), allow_rule("echo")]);
    let result = evaluate_with_env(
        r#"while true; do x="a"; done; echo $x"#,
        &config,
        &env,
    );
    assert_eq!(result.decision, Decision::Ask);
}

// ── read/readarray builtins ─────────────────────────────────────

#[test]
fn read_herestring_literal_allows() {
    // read x <<< "hello"; echo $x → Allow
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"read x <<< "hello"; echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn read_no_herestring_safe_opaque() {
    // read x; echo $x → Allow (safe+opaque)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env("read x; echo $x", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn read_with_flags_skipped() {
    // read -r x <<< "hello"; echo $x → Allow (flags skipped)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"read -r x <<< "hello"; echo $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn read_default_reply_var() {
    // read <<< "hello"; echo $REPLY → Allow
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate_with_env(r#"read <<< "hello"; echo $REPLY"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Code-execution position detection ───────────────────────────

#[test]
fn eval_literal_allowed_cmd() {
    // x="ls"; eval $x → Allow (x resolves to "ls", eval'd "ls" checked against rules)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate_with_env(r#"x="ls"; eval $x"#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn eval_unsafe_var_asks() {
    // eval $UNKNOWN → Ask
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate_with_env("eval $UNKNOWN", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn eval_literal_with_args() {
    // x="ls"; eval "$x -la" → Allow (resolves to "ls -la")
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate_with_env(r#"x="ls"; eval "$x -la""#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn opaque_var_as_command_name_asks() {
    // $x where x is safe but opaque → Ask (can't determine what runs)
    let env = env_with(&[("x", VarState::Safe(None))]);
    let config = config_with_rules(vec![allow_rule("ls")]);
    let result = evaluate_with_env("$x", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("command name"), "should mention command name: {reason}");
}

#[test]
fn bash_dash_c_literal_evaluates() {
    // x="ls"; bash -c "$x" → Allow (x resolves, inner "ls" evaluated)
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("ls"), allow_rule("bash")]);
    let result = evaluate_with_env(r#"x="ls"; bash -c "$x""#, &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn bash_dash_c_unsafe_asks() {
    // bash -c "$UNKNOWN" → Ask
    let env = VarEnv::empty();
    let config = config_with_rules(vec![allow_rule("bash")]);
    let result = evaluate_with_env(r#"bash -c "$UNKNOWN""#, &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn source_always_asks() {
    let config = config_with_rules(vec![allow_rule("source")]);
    let result = evaluate("source ./script.sh", &config);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("source"), "should mention source: {reason}");
}

#[test]
fn dot_source_always_asks() {
    let config = config_with_rules(vec![allow_rule(".")]);
    let result = evaluate(". ./script.sh", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn eval_opaque_var_asks() {
    // eval with opaque arg asks
    let env = env_with(&[("cmd", VarState::Safe(None))]);
    let config = config_with_rules(vec![allow_rule("eval"), allow_rule("ls")]);
    let result = evaluate_with_env("eval $cmd", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
    let reason = result.reason.unwrap();
    assert!(reason.contains("eval"), "should mention eval: {reason}");
}

#[test]
fn sh_dash_c_opaque_asks() {
    let env = env_with(&[("cmd", VarState::Safe(None))]);
    let config = config_with_rules(vec![allow_rule("sh")]);
    let result = evaluate_with_env("sh -c $cmd", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn bash_no_dash_c_evaluates_normally() {
    // bash without -c is not a code-execution pattern
    let config = config_with_rules(vec![allow_rule("bash")]);
    let result = evaluate("bash script.sh", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn eval_empty_allows() {
    let config = config_with_rules(vec![allow_rule("eval")]);
    let result = evaluate("eval", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn eval_denied_inner_denies() {
    let config = config_with_rules(vec![deny_rule("rm")]);
    let result = evaluate("eval rm -rf /", &config);
    assert_eq!(result.decision, Decision::Deny);
}

// ── Process substitution safety ──────────────────────────────────

#[test]
fn process_sub_safe_inner_allows() {
    let config = config_with_rules(vec![allow_rule("diff"), allow_rule("echo")]);
    let result = evaluate("diff <(echo a) <(echo b)", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn process_sub_unsafe_inner_asks() {
    let config = config_with_rules(vec![allow_rule("diff")]);
    // dangerous_cmd has no rule → Ask
    let result = evaluate("diff <(dangerous_cmd) file", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn process_sub_cat_echo_allows() {
    let config = config_with_rules(vec![allow_rule("cat"), allow_rule("echo")]);
    let result = evaluate("cat <(echo safe)", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn process_sub_output_direction_allows() {
    let config = config_with_rules(vec![allow_rule("tee"), allow_rule("echo")]);
    let result = evaluate("echo hello | tee >(cat)", &config);
    assert_eq!(result.decision, Decision::Ask); // cat has no rule
}

#[test]
fn process_sub_output_all_allowed() {
    let config = config_with_rules(vec![allow_rule("tee"), allow_rule("echo"), allow_rule("cat")]);
    let result = evaluate("echo hello | tee >(cat)", &config);
    assert_eq!(result.decision, Decision::Allow);
}

// ── Arithmetic expression safety ─────────────────────────────────

#[test]
fn arithmetic_pure_numeric_allows() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("echo $((1 + 2))", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn arithmetic_safe_var_allows() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
    let result = evaluate_with_env("x=5; echo $((x + 1))", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn arithmetic_unknown_var_asks() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let env = VarEnv::empty();
    let result = evaluate_with_env("echo $((UNKNOWN + 1))", &config, &env);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn arithmetic_safe_var_complex_allows() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
    let result = evaluate_with_env("x=5; echo $((x * 2 + 1))", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn arithmetic_dollar_var_safe() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let env = env_with(&[("y", VarState::Safe(Some("3".into())))]);
    let result = evaluate_with_env("echo $(($y + 1))", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn arithmetic_dollar_brace_var_safe() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let env = env_with(&[("z", VarState::Safe(Some("7".into())))]);
    let result = evaluate_with_env("echo $((${z} + 1))", &config, &env);
    assert_eq!(result.decision, Decision::Allow);
}

// ── is_arithmetic_safe unit tests ────────────────────────────────

#[test]
fn arith_safe_pure_numbers() {
    let env = VarEnv::empty();
    assert!(is_arithmetic_safe("1 + 2 * 3", &env));
}

#[test]
fn arith_safe_known_var() {
    let env = env_with(&[("x", VarState::Safe(Some("5".into())))]);
    assert!(is_arithmetic_safe("x + 1", &env));
}

#[test]
fn arith_unsafe_unknown_var() {
    let env = VarEnv::empty();
    assert!(!is_arithmetic_safe("x + 1", &env));
}

#[test]
fn arith_safe_dollar_var() {
    let env = env_with(&[("y", VarState::Safe(None))]);
    assert!(is_arithmetic_safe("$y + 1", &env));
}

#[test]
fn arith_safe_dollar_brace_var() {
    let env = env_with(&[("z", VarState::Safe(None))]);
    assert!(is_arithmetic_safe("${z} * 2", &env));
}

#[test]
fn arith_unsafe_dollar_var() {
    let env = VarEnv::empty();
    assert!(!is_arithmetic_safe("$UNKNOWN + 1", &env));
}

// ── Function tracking ────────────────────────────────────────────

#[test]
fn function_def_then_call_allows() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("f() { echo hello; }; f", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn function_def_then_call_denies() {
    let config = config_with_rules(vec![deny_rule("rm")]);
    let result = evaluate("f() { rm -rf /; }; f", &config);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn function_def_then_call_with_safe_arg() {
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("f() { echo $1; }; f safe", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn function_def_then_call_unknown_inner() {
    // Inner command has no matching rule → Ask
    let config = config_with_rules(vec![]);
    let result = evaluate("f() { dangerous; }; f", &config);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn function_def_never_called_allows() {
    let config = config_with_rules(vec![deny_rule("rm")]);
    // Function is defined but never called — definition is safe
    let result = evaluate("f() { rm -rf /; }", &config);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn function_recursive_depth_guard() {
    // Recursive function should hit depth guard and not loop infinitely
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("f() { f; }; f", &config);
    // At max depth, the recursive call to `f` won't find it as a function
    // (depth >= MAX_EVAL_DEPTH), so it falls through to rule matching,
    // which yields Ask (no rule for `f`)
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn function_propagates_env() {
    // Function body sets a variable that's used after the call
    let config = config_with_rules(vec![allow_rule("echo")]);
    let result = evaluate("f() { x=hello; }; f; echo $x", &config);
    assert_eq!(result.decision, Decision::Allow);
}

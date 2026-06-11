use crate::*;

#[test]
fn test_parse_simple_command() {
    let cmd = parse("echo hello world").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("echo"));
            assert_eq!(sc.args().len(), 2);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_empty_input() {
    let cmd = parse("").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words.is_empty());
            assert!(sc.assignments.is_empty());
            assert!(sc.redirections.is_empty());
        }
        _ => panic!("Expected empty simple command"),
    }
}

#[test]
fn test_whitespace_only() {
    let cmd = parse("   \t  ").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words.is_empty());
        }
        _ => panic!("Expected empty simple command"),
    }
}

// --- Pipelines ---

#[test]
fn test_pipeline() {
    let cmd = parse("echo foo | grep bar").into_command();
    match &cmd {
        Command::Pipeline(cmds) => {
            assert_eq!(cmds.len(), 2);
            match &cmds[0] {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple command in pipeline"),
            }
            match &cmds[1] {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("grep")),
                _ => panic!("Expected simple command in pipeline"),
            }
        }
        _ => panic!("Expected pipeline"),
    }
}

#[test]
fn test_pipeline_three_commands() {
    let cmd = parse("cat file | sort | uniq").into_command();
    match &cmd {
        Command::Pipeline(cmds) => assert_eq!(cmds.len(), 3),
        _ => panic!("Expected pipeline"),
    }
}

// --- And / Or ---

#[test]
fn test_and() {
    let cmd = parse("cmd1 && cmd2").into_command();
    match &cmd {
        Command::And(left, right) => {
            match left.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd1")),
                _ => panic!("Expected simple command"),
            }
            match right.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd2")),
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected And command"),
    }
}

#[test]
fn test_or() {
    let cmd = parse("cmd1 || cmd2").into_command();
    match &cmd {
        Command::Or(left, right) => {
            match left.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd1")),
                _ => panic!("Expected simple command"),
            }
            match right.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd2")),
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected Or command"),
    }
}

#[test]
fn test_and_or_chained() {
    let cmd = parse("a && b || c").into_command();
    match &cmd {
        Command::Or(left, _) => match left.as_ref() {
            Command::And(_, _) => {}
            _ => panic!("Expected And inside Or"),
        },
        _ => panic!("Expected Or command"),
    }
}

// --- Sequences ---

#[test]
fn test_sequence() {
    let cmd = parse("cmd1; cmd2; cmd3").into_command();
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 3);
        }
        _ => panic!("Expected sequence, got {:?}", cmd),
    }
}

#[test]
fn test_sequence_trailing_semi() {
    let cmd = parse("cmd1; cmd2;").into_command();
    match &cmd {
        Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
        _ => panic!("Expected sequence"),
    }
}

// --- Background ---

#[test]
fn test_background() {
    let cmd = parse("sleep 10 &").into_command();
    match &cmd {
        Command::Background(inner) => match inner.as_ref() {
            Command::Simple(sc) => assert_eq!(sc.command_name(), Some("sleep")),
            _ => panic!("Expected simple command"),
        },
        _ => panic!("Expected background command"),
    }
}

#[test]
fn test_background_in_sequence() {
    let cmd = parse("cmd1 & cmd2").into_command();
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 2);
            match &cmds[0] {
                Command::Background(_) => {}
                _ => panic!("Expected background"),
            }
        }
        _ => panic!("Expected sequence"),
    }
}

// --- Subshell ---

#[test]
fn test_subshell() {
    let cmd = parse("(cmd1; cmd2)").into_command();
    match &cmd {
        Command::Subshell(inner) => match inner.as_ref() {
            Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
            _ => panic!("Expected sequence inside subshell"),
        },
        _ => panic!("Expected subshell"),
    }
}

#[test]
fn test_subshell_single_command() {
    let cmd = parse("(echo hello)").into_command();
    match &cmd {
        Command::Subshell(inner) => match inner.as_ref() {
            Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
            _ => panic!("Expected simple command"),
        },
        _ => panic!("Expected subshell"),
    }
}

// --- Brace group ---

#[test]
fn test_brace_group() {
    let cmd = parse("{ cmd1; cmd2; }").into_command();
    match &cmd {
        Command::BraceGroup(inner) => match inner.as_ref() {
            Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
            _ => panic!("Expected sequence inside brace group"),
        },
        _ => panic!("Expected brace group"),
    }
}

// --- If / elif / else ---

#[test]
fn test_if_then_fi() {
    let cmd = parse("if true; then echo yes; fi").into_command();
    match &cmd {
        Command::If {
            condition,
            then_branch,
            elif_branches,
            else_branch,
        } => {
            match condition.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("true")),
                _ => panic!("Expected simple condition"),
            }
            match then_branch.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple then branch"),
            }
            assert!(elif_branches.is_empty());
            assert!(else_branch.is_none());
        }
        _ => panic!("Expected if command"),
    }
}

#[test]
fn test_if_else() {
    let cmd = parse("if true; then echo yes; else echo no; fi").into_command();
    match &cmd {
        Command::If { else_branch, .. } => {
            assert!(else_branch.is_some());
        }
        _ => panic!("Expected if command"),
    }
}

#[test]
fn test_if_elif_else() {
    let cmd = parse("if a; then b; elif c; then d; elif e; then f; else g; fi").into_command();
    match &cmd {
        Command::If {
            elif_branches,
            else_branch,
            ..
        } => {
            assert_eq!(elif_branches.len(), 2);
            assert!(else_branch.is_some());
        }
        _ => panic!("Expected if command"),
    }
}

// --- For loop ---

#[test]
fn test_for_loop() {
    let cmd = parse("for x in a b c; do echo $x; done").into_command();
    match &cmd {
        Command::For { var, words, body } => {
            assert_eq!(var, "x");
            assert_eq!(words.len(), 3);
            assert_eq!(words[0].to_str(), "a");
            assert_eq!(words[1].to_str(), "b");
            assert_eq!(words[2].to_str(), "c");
            match body.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple body"),
            }
        }
        _ => panic!("Expected for command"),
    }
}

// --- While loop ---

#[test]
fn test_while_loop() {
    let cmd = parse("while true; do echo loop; done").into_command();
    match &cmd {
        Command::Loop {
            kind: LoopKind::While,
            condition,
            body,
        } => {
            match condition.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("true")),
                _ => panic!("Expected simple condition"),
            }
            match body.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple body"),
            }
        }
        _ => panic!("Expected while command"),
    }
}

// --- Until loop ---

#[test]
fn test_until_loop() {
    let cmd = parse("until false; do echo loop; done").into_command();
    match &cmd {
        Command::Loop {
            kind: LoopKind::Until,
            condition,
            body,
        } => {
            match condition.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("false")),
                _ => panic!("Expected simple condition"),
            }
            match body.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple body"),
            }
        }
        _ => panic!("Expected until command"),
    }
}

// --- Case statement ---

#[test]
fn test_case_basic() {
    let cmd = parse("case $x in a) echo a;; b) echo b;; esac").into_command();
    match &cmd {
        Command::Case { word, arms } => {
            assert!(word.has_dynamic_parts()); // $x is dynamic
            assert_eq!(arms.len(), 2);
            assert_eq!(arms[0].patterns[0].to_str(), "a");
            assert_eq!(arms[0].terminator, CaseTerminator::Break);
            assert_eq!(arms[1].patterns[0].to_str(), "b");
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_multiple_patterns() {
    let cmd = parse("case $x in a|b) echo ab;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms[0].patterns.len(), 2);
            assert_eq!(arms[0].patterns[0].to_str(), "a");
            assert_eq!(arms[0].patterns[1].to_str(), "b");
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_fallthrough() {
    let cmd = parse("case $x in a) echo a;& b) echo b;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms[0].terminator, CaseTerminator::Fallthrough);
            assert_eq!(arms[1].terminator, CaseTerminator::Break);
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_continue() {
    let cmd = parse("case $x in a) echo a;;& b) echo b;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms[0].terminator, CaseTerminator::Continue);
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_glob_pattern() {
    let cmd = parse("case $x in *) echo default;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms.len(), 1);
            // The * is parsed as a glob
            assert!(
                arms[0].patterns[0]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Glob(_)))
            );
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_empty_body() {
    let cmd = parse("case $x in a) ;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert!(arms[0].body.is_none());
        }
        _ => panic!("Expected case command"),
    }
}

// --- Function definitions ---

#[test]
fn test_function_def() {
    let cmd = parse("function foo() { echo hello; }").into_command();
    match &cmd {
        Command::FunctionDef { name, body } => {
            assert_eq!(name, "foo");
            match body.as_ref() {
                Command::BraceGroup(_) => {}
                _ => panic!("Expected brace group body"),
            }
        }
        _ => panic!("Expected function def"),
    }
}

#[test]
fn test_function_def_no_parens() {
    let cmd = parse("function bar { echo hi; }").into_command();
    match &cmd {
        Command::FunctionDef { name, .. } => {
            assert_eq!(name, "bar");
        }
        _ => panic!("Expected function def"),
    }
}

// --- Assignments ---

#[test]
fn test_assignment_standalone() {
    let cmd = parse("VAR=value").into_command();
    match &cmd {
        Command::Assignment(a) => {
            assert_eq!(a.name, "VAR");
            assert_eq!(a.value.to_str(), "value");
        }
        _ => panic!("Expected assignment, got {:?}", cmd),
    }
}

#[test]
fn test_assignment_empty_value() {
    let cmd = parse("VAR=").into_command();
    match &cmd {
        Command::Assignment(a) => {
            assert_eq!(a.name, "VAR");
            assert_eq!(a.value.to_str(), "");
        }
        _ => panic!("Expected assignment"),
    }
}

#[test]
fn test_assignment_with_command() {
    let cmd = parse("VAR=value cmd arg").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.assignments.len(), 1);
            assert_eq!(sc.assignments[0].name, "VAR");
            assert_eq!(sc.assignments[0].value.to_str(), "value");
            assert_eq!(sc.command_name(), Some("cmd"));
            assert_eq!(sc.args().len(), 1);
        }
        _ => panic!("Expected simple command with assignment"),
    }
}

// --- Comments ---

#[test]
fn test_comment() {
    let cmd = parse("echo foo # this is a comment").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("echo"));
            assert_eq!(sc.args().len(), 1);
            assert_eq!(sc.args()[0].to_str(), "foo");
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_comment_only() {
    let cmd = parse("# just a comment").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words.is_empty());
        }
        _ => panic!("Expected empty simple command"),
    }
}

#[test]
fn hash_mid_word_is_literal() {
    // POSIX 2.3: `#` starts a comment only at a token boundary. Mid-word it
    // is a literal character.
    let cmd = parse("a#cat").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("a#cat"));
            assert!(sc.args().is_empty());
        }
        _ => panic!("Expected simple command, got {cmd:?}"),
    }
}

#[test]
fn hash_after_whitespace_is_comment() {
    let cmd = parse("echo hi # not a word").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("echo"));
            assert_eq!(sc.args().len(), 1);
            assert_eq!(sc.args()[0].to_str(), "hi");
        }
        _ => panic!("Expected simple command, got {cmd:?}"),
    }
}

#[test]
fn hash_inside_single_quotes_is_literal() {
    let cmd = parse("echo 'a # not comment'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("echo"));
            assert_eq!(sc.args().len(), 1);
            assert_eq!(sc.args()[0].to_str(), "a # not comment");
        }
        _ => panic!("Expected simple command, got {cmd:?}"),
    }
}

#[test]
fn hash_mid_word_with_heredoc() {
    // Regression: `a#cat <<'A'\nbody\nA` must parse as one SimpleCommand
    // with command name `a#cat` and a heredoc redirect; the body bytes must
    // never be re-parsed as commands.
    let pr = parse("a#cat <<'A'\nbody\nA");
    let cmd = pr.into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("a#cat"));
            assert_eq!(sc.redirections.len(), 1);
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "body\n");
                }
                other => panic!("Expected heredoc target, got {other:?}"),
            }
        }
        other => panic!("Expected single SimpleCommand, got {other:?}"),
    }
}

// --- extract_simple_commands ---

#[test]
fn test_extract_simple_commands_from_pipeline() {
    let cmd = parse("echo foo | grep bar | wc -l").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
    assert_eq!(scs[0].command_name(), Some("echo"));
    assert_eq!(scs[1].command_name(), Some("grep"));
    assert_eq!(scs[2].command_name(), Some("wc"));
}

#[test]
fn test_extract_simple_commands_from_and_or() {
    let cmd = parse("a && b || c").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
}

#[test]
fn test_extract_simple_commands_from_sequence() {
    let cmd = parse("a; b; c").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
}

#[test]
fn test_extract_simple_commands_from_if() {
    let cmd = parse("if a; then b; elif c; then d; else e; fi").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 5); // a, b, c, d, e
}

#[test]
fn test_extract_simple_commands_from_for() {
    let cmd = parse("for x in a b; do echo $x; done").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1); // just the echo
}

#[test]
fn test_extract_simple_commands_from_while() {
    let cmd = parse("while true; do echo loop; done").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
    assert_eq!(scs[0].command_name(), Some("true"));
    assert_eq!(scs[1].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_until() {
    let cmd = parse("until false; do echo loop; done").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
    assert_eq!(scs[0].command_name(), Some("false"));
    assert_eq!(scs[1].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_case() {
    let cmd = parse("case $x in a) echo a;; b) echo b;; esac").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
}

#[test]
fn test_extract_simple_commands_from_function() {
    let cmd = parse("function foo() { echo hello; }").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
    assert_eq!(scs[0].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_background() {
    let cmd = parse("sleep 10 &").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
    assert_eq!(scs[0].command_name(), Some("sleep"));
}

#[test]
fn test_extract_simple_commands_from_subshell() {
    let cmd = parse("(echo hello)").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
}

#[test]
fn test_extract_simple_commands_from_brace_group() {
    let cmd = parse("{ echo hello; }").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
}

#[test]
fn test_extract_simple_commands_from_assignment() {
    let cmd = parse("FOO=bar").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 0); // assignments don't contain simple commands
}

// --- extract_all_words ---

#[test]
fn test_extract_all_words_simple() {
    let cmd = parse("echo hello world").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_with_redirections() {
    let cmd = parse("echo hello > file.txt").into_command();
    let words = extract_all_words(&cmd);
    // echo, hello, file.txt (redirect target)
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_with_assignment() {
    let cmd = parse("VAR=value cmd arg").into_command();
    let words = extract_all_words(&cmd);
    // assignment value + cmd + arg
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_standalone_assignment() {
    let cmd = parse("VAR=value").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1); // just the assignment value
}

#[test]
fn test_extract_all_words_from_for() {
    let cmd = parse("for x in a b c; do echo $x; done").into_command();
    let words = extract_all_words(&cmd);
    // a, b, c (for-loop words) + echo, $x (body words)
    assert_eq!(words.len(), 5);
}

#[test]
fn test_extract_all_words_from_case() {
    let cmd = parse("case $x in a) echo hello;; esac").into_command();
    let words = extract_all_words(&cmd);
    // $x (case word) + a (pattern) + echo, hello (body words)
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_from_pipeline() {
    let cmd = parse("echo a | grep b").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 4); // echo, a, grep, b
}

#[test]
fn test_extract_all_words_from_and_or() {
    let cmd = parse("cmd1 arg1 && cmd2 arg2").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_from_background() {
    let cmd = parse("echo hello &").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn test_extract_all_words_from_subshell() {
    let cmd = parse("(echo hello)").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn test_extract_all_words_from_if() {
    let cmd = parse("if true; then echo yes; else echo no; fi").into_command();
    let words = extract_all_words(&cmd);
    // true, echo, yes, echo, no
    assert_eq!(words.len(), 5);
}

#[test]
fn test_extract_all_words_from_while() {
    let cmd = parse("while true; do echo x; done").into_command();
    let words = extract_all_words(&cmd);
    // true, echo, x
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_from_function() {
    let cmd = parse("function foo() { echo bar; }").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2); // echo, bar
}

// --- Complex / combined constructs ---

#[test]
fn test_pipeline_with_redirections() {
    let cmd = parse("cat < input.txt | sort > output.txt").into_command();
    match &cmd {
        Command::Pipeline(cmds) => {
            assert_eq!(cmds.len(), 2);
            match &cmds[0] {
                Command::Simple(sc) => {
                    assert_eq!(sc.command_name(), Some("cat"));
                    assert_eq!(sc.redirections.len(), 1);
                    assert_eq!(sc.redirections[0].kind, RedirectionKind::Input);
                }
                _ => panic!("Expected simple command"),
            }
            match &cmds[1] {
                Command::Simple(sc) => {
                    assert_eq!(sc.command_name(), Some("sort"));
                    assert_eq!(sc.redirections.len(), 1);
                    assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
                }
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected pipeline"),
    }
}

#[test]
fn test_complex_nested_structure() {
    let cmd = parse("if true; then for x in a b; do echo $x; done; fi").into_command();
    match &cmd {
        Command::If { then_branch, .. } => match then_branch.as_ref() {
            Command::For { var, words, .. } => {
                assert_eq!(var, "x");
                assert_eq!(words.len(), 2);
            }
            _ => panic!("Expected for loop in then branch"),
        },
        _ => panic!("Expected if command"),
    }
}

#[test]
fn test_newline_separated_commands() {
    // Multiple commands separated by semicolons produce a sequence
    let cmd = parse("echo a; echo b; echo c").into_command();
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 3);
            for c in cmds {
                match c {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple command in sequence"),
                }
            }
        }
        _ => panic!("Expected sequence"),
    }
}

#[test]
fn test_extract_all_words_redirect_fd_target() {
    let cmd = parse("cmd >&2").into_command();
    let words = extract_all_words(&cmd);
    // cmd word only; Fd(2) is not a File target so not collected
    assert_eq!(words.len(), 1);
}

#[test]
fn test_case_with_empty_body_arm() {
    let cmd = parse("case $x in a) ;; b) echo b;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms.len(), 2);
            assert!(arms[0].body.is_none());
            assert!(arms[1].body.is_some());
        }
        _ => panic!("Expected case"),
    }
}

#[test]
fn test_extract_simple_commands_case_empty_body() {
    let cmd = parse("case $x in a) ;; esac").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 0);
}

#[test]
fn test_if_without_else() {
    let cmd = parse("if true; then echo yes; fi").into_command();
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2); // true + echo
}

#[test]
fn test_extract_all_words_elif() {
    let cmd = parse("if a; then b; elif c; then d; fi").into_command();
    let words = extract_all_words(&cmd);
    // a, b, c, d
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_until() {
    let cmd = parse("until false; do echo x; done").into_command();
    let words = extract_all_words(&cmd);
    // false, echo, x
    assert_eq!(words.len(), 3);
}

// -- structural dynamic parts in control flow --

#[test]
fn structural_dynamic_case_arms() {
    use std::collections::HashMap;
    let cmd = parse("case $x in $pat) echo hi ;; esac").into_command();
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$x".to_string()));
    assert!(parts.contains(&"$pat".to_string()));
}

#[test]
fn structural_dynamic_elif_else() {
    use std::collections::HashMap;
    let cmd =
        parse("if true; then echo a; elif $cond; then echo b; else echo c; fi").into_command();
    let _parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
}

#[test]
fn structural_dynamic_function_body() {
    use std::collections::HashMap;
    let cmd = parse("function foo { for x in $items; do echo $x; done; }").into_command();
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$items".to_string()));
}

#[test]
fn structural_dynamic_redirected() {
    use std::collections::HashMap;
    let cmd = parse("for x in $items; do echo $x; done > /tmp/out").into_command();
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$items".to_string()));
}

// -- extract_simple_commands / extract_all_words edge cases --

#[test]
fn extract_simple_commands_from_redirected() {
    let cmd = parse("echo hello > /tmp/out").into_command();
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

#[test]
fn extract_simple_commands_from_compound_redirected() {
    let cmd = parse("{ echo hello; } > /tmp/out").into_command();
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

#[test]
fn extract_all_words_from_redirected() {
    let cmd = parse("echo hello > /tmp/out").into_command();
    let words = extract_all_words(&cmd);
    assert!(words.len() >= 3);
}

#[test]
fn extract_all_words_from_compound_redirected() {
    let cmd = parse("{ echo hello; } > /tmp/out").into_command();
    let words = extract_all_words(&cmd);
    assert!(words.len() >= 3);
}

#[test]
fn extract_all_words_from_compound_with_heredoc_redirect() {
    let cmd = parse("{ cat; } <<'EOF'\nhello\nEOF\n").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1);
}

#[test]
fn extract_all_words_from_compound_with_fd_redirect() {
    let cmd = parse("{ echo hi; } 2>&1").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn extract_all_words_from_standalone_assignment_value() {
    let cmd = parse("x=hello").into_command();
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1);
    assert_eq!(words[0].to_str(), "hello");
}

// -- newline / background in parse_list --

#[test]
fn newline_separated_commands_in_sequence() {
    let cmd = parse("echo a\necho b").into_command();
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 2);
        }
        _ => panic!("Expected sequence, got {:?}", cmd),
    }
}

#[test]
fn background_command_in_sequence() {
    let cmd = parse("sleep 1 & echo done").into_command();
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 2);
            assert!(matches!(&cmds[0], Command::Background(_)));
            match &cmds[1] {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected sequence, got {:?}", cmd),
    }
}

// -- case with optional leading ( --

#[test]
fn case_with_leading_paren_in_pattern() {
    let cmd = parse("case x in (a) echo a ;; esac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms.len(), 1);
            assert_eq!(arms[0].patterns[0].to_str(), "a");
        }
        _ => panic!("Expected case"),
    }
}

// -- case with default terminator (no ;; at end) --

#[test]
fn case_arm_without_terminator() {
    let cmd = parse("case x in a) echo a\nesac").into_command();
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms.len(), 1);
        }
        _ => panic!("Expected case"),
    }
}

// -- edge case: for with missing var name --

#[test]
fn for_loop_missing_var_name() {
    let cmd = parse("for ; do echo x; done").into_command();
    match &cmd {
        Command::For { var, .. } => {
            assert!(var.is_empty());
        }
        _ => panic!("Expected for loop, got {:?}", cmd),
    }
}

// -- edge case: case with empty word --

#[test]
fn case_empty_discriminant() {
    let cmd = parse("case\nin a) echo x ;; esac").into_command();
    match &cmd {
        Command::Case { word, .. } => {
            let _ = word;
        }
        _ => panic!("Expected case"),
    }
}

// -- edge case: function with missing name --

#[test]
fn function_missing_name() {
    let cmd = parse("function { echo x; }").into_command();
    match &cmd {
        Command::FunctionDef { name, .. } => {
            assert!(name.is_empty());
        }
        _ => panic!("Expected function def, got {:?}", cmd),
    }
}

// -- comment before newline in lexer --

#[test]
fn comment_then_newline_then_command() {
    let cmd = parse("# comment\necho hello").into_command();
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

// -- function definitions --

#[test]
fn function_definition_parsed() {
    let cmd = parse("greet() { echo hi; }").into_command();
    match &cmd {
        Command::FunctionDef { name, body } => {
            assert_eq!(name, "greet");
            let cmds = extract_simple_commands(body);
            assert_eq!(cmds.len(), 1);
            assert_eq!(cmds[0].command_name(), Some("echo"));
        }
        _ => panic!("Expected function def, got {:?}", cmd),
    }
}

// --- Glob patterns in parsed words ---

#[test]
fn test_glob_star() {
    let cmd = parse("echo *.txt").into_command();
    match &cmd {
        Command::Simple(sc) => {
            let word = &sc.words[1];
            assert!(
                word.parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Glob(s) if s == "*"))
            );
            assert!(
                word.parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Literal(s) if s == ".txt"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_glob_question() {
    let cmd = parse("echo file?.txt").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Glob(s) if s == "?"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_glob_bracket() {
    let cmd = parse("echo [abc].txt").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Glob(s) if s == "[abc]"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// --- [ as a command (test builtin) ---

#[test]
fn test_bracket_command() {
    // `[` is a shell builtin command, not a glob bracket expression.
    let cmd = parse("[ -f foo ]").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("["));
            assert_eq!(
                sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(),
                vec!["-f", "foo", "]"]
            );
        }
        _ => panic!("Expected simple command, got: {cmd:?}"),
    }
}

#[test]
fn test_bracket_command_in_if() {
    // `[ -f foo ]` used as a condition in an if statement.
    let cmd = parse("if [ -f foo ]; then echo yes; fi").into_command();
    match &cmd {
        Command::If { condition, .. } => {
            // The condition should contain the `[` command
            match condition.as_ref() {
                Command::Simple(sc) => {
                    assert_eq!(sc.command_name(), Some("["));
                    assert_eq!(
                        sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(),
                        vec!["-f", "foo", "]"]
                    );
                }
                other => panic!("Expected simple command as condition, got: {other:?}"),
            }
        }
        _ => panic!("Expected if command, got: {cmd:?}"),
    }
}

#[test]
fn test_double_bracket_command() {
    // `[[` is a bash keyword, not a glob expression.
    let cmd = parse("[[ -f foo ]]").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("[["));
            assert_eq!(
                sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(),
                vec!["-f", "foo", "]]"]
            );
        }
        _ => panic!("Expected simple command, got: {cmd:?}"),
    }
}

#[test]
fn test_double_bracket_in_if() {
    let cmd = parse("if [[ -f foo ]]; then echo yes; fi").into_command();
    match &cmd {
        Command::If { condition, .. } => match condition.as_ref() {
            Command::Simple(sc) => {
                assert_eq!(sc.command_name(), Some("[["));
                assert_eq!(
                    sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(),
                    vec!["-f", "foo", "]]"]
                );
            }
            other => panic!("Expected simple command as condition, got: {other:?}"),
        },
        _ => panic!("Expected if command, got: {cmd:?}"),
    }
}

// -- Lexer: ${#@} where # is not followed by identifier+} --

#[test]
fn parse_param_expansion_hash_not_length() {
    // ${#} — '#' with no identifier is not length op, falls back to flat
    let cmd = parse("echo ${#}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansion("#".into())]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_hash_special() {
    // ${#*} — '#' followed by '*' (not a valid identifier), falls through
    let cmd = parse("echo ${#*}").into_command();
    if let Command::Simple(sc) = &cmd {
        // '#' not followed by ident+'}', so it restores pos and reads '#*' as flat
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansion("#*".into())]
        );
    } else {
        panic!("Expected simple command");
    }
}

// -- Process-substitution redirect target does not desync compounds --

fn command_names(input: &str) -> Vec<String> {
    crate::extract_simple_commands(&parse(input).into_command())
        .iter()
        .filter_map(|sc| sc.command_name().map(str::to_string))
        .collect()
}

#[test]
fn procsub_redirect_in_function_body_keeps_trailing_command() {
    let input = "f() { while read x; do :; done < <(find .); rm -rf /danger; }";
    let result = parse(input);
    assert!(
        !result.diagnostics.iter().any(|d| matches!(
            d.kind,
            crate::diagnostic::ParseDiagnosticKind::MissingClosingKeyword { .. }
        )),
        "unexpected MissingClosingKeyword: {:?}",
        result.diagnostics
    );
    assert!(
        command_names(input).iter().any(|c| c == "rm"),
        "trailing `rm` was dropped; got {:?}",
        command_names(input)
    );
}

#[test]
fn procsub_herestring_in_function_body_keeps_trailing_command() {
    // `<<< <(cmd)` — herestring whose word is a process substitution. The
    // target reader must consume the whole `<( … )` here too, or the stray
    // procsub word desyncs the enclosing group exactly like the `< <(…)`
    // case.
    let input = "f() { while read x; do :; done <<< <(find .); rm x; }";
    let result = parse(input);
    assert!(
        !result.diagnostics.iter().any(|d| matches!(
            d.kind,
            crate::diagnostic::ParseDiagnosticKind::MissingClosingKeyword { .. }
        )),
        "unexpected MissingClosingKeyword: {:?}",
        result.diagnostics
    );
    assert!(
        command_names(input).iter().any(|c| c == "rm"),
        "trailing `rm` was dropped; got {:?}",
        command_names(input)
    );
}

#[test]
fn procsub_redirect_in_subshell_keeps_trailing_command() {
    let input = "( while read x; do :; done < <(find .); rm x )";
    assert!(
        command_names(input).iter().any(|c| c == "rm"),
        "trailing `rm` was dropped; got {:?}",
        command_names(input)
    );
}

#[test]
fn command_substitution_redirect_target_keeps_trailing_command() {
    // Regression guard: the `$( … )` redirect-target case already parses
    // correctly and must keep its trailing `rm`.
    let input = "f() { while read x; do :; done < \"$(echo f)\"; rm x; }";
    assert!(
        command_names(input).iter().any(|c| c == "rm"),
        "trailing `rm` was dropped; got {:?}",
        command_names(input)
    );
}

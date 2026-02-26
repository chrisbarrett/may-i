use super::*;
use super::glob::{glob_match, glob_replace, glob_strip_prefix, glob_strip_suffix};

#[test]
fn test_parse_simple_command() {
    let cmd = parse("echo hello world");
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
    let cmd = parse("");
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
    let cmd = parse("   \t  ");
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
    let cmd = parse("echo foo | grep bar");
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
    let cmd = parse("cat file | sort | uniq");
    match &cmd {
        Command::Pipeline(cmds) => assert_eq!(cmds.len(), 3),
        _ => panic!("Expected pipeline"),
    }
}

// --- And / Or ---

#[test]
fn test_and() {
    let cmd = parse("cmd1 && cmd2");
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
    let cmd = parse("cmd1 || cmd2");
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
    let cmd = parse("a && b || c");
    match &cmd {
        Command::Or(left, _) => {
            match left.as_ref() {
                Command::And(_, _) => {}
                _ => panic!("Expected And inside Or"),
            }
        }
        _ => panic!("Expected Or command"),
    }
}

// --- Sequences ---

#[test]
fn test_sequence() {
    let cmd = parse("cmd1; cmd2; cmd3");
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 3);
        }
        _ => panic!("Expected sequence, got {:?}", cmd),
    }
}

#[test]
fn test_sequence_trailing_semi() {
    let cmd = parse("cmd1; cmd2;");
    match &cmd {
        Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
        _ => panic!("Expected sequence"),
    }
}

// --- Background ---

#[test]
fn test_background() {
    let cmd = parse("sleep 10 &");
    match &cmd {
        Command::Background(inner) => {
            match inner.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("sleep")),
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected background command"),
    }
}

#[test]
fn test_background_in_sequence() {
    let cmd = parse("cmd1 & cmd2");
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
    let cmd = parse("(cmd1; cmd2)");
    match &cmd {
        Command::Subshell(inner) => {
            match inner.as_ref() {
                Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
                _ => panic!("Expected sequence inside subshell"),
            }
        }
        _ => panic!("Expected subshell"),
    }
}

#[test]
fn test_subshell_single_command() {
    let cmd = parse("(echo hello)");
    match &cmd {
        Command::Subshell(inner) => {
            match inner.as_ref() {
                Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                _ => panic!("Expected simple command"),
            }
        }
        _ => panic!("Expected subshell"),
    }
}

// --- Brace group ---

#[test]
fn test_brace_group() {
    let cmd = parse("{ cmd1; cmd2; }");
    match &cmd {
        Command::BraceGroup(inner) => {
            match inner.as_ref() {
                Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
                _ => panic!("Expected sequence inside brace group"),
            }
        }
        _ => panic!("Expected brace group"),
    }
}

// --- If / elif / else ---

#[test]
fn test_if_then_fi() {
    let cmd = parse("if true; then echo yes; fi");
    match &cmd {
        Command::If { condition, then_branch, elif_branches, else_branch } => {
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
    let cmd = parse("if true; then echo yes; else echo no; fi");
    match &cmd {
        Command::If { else_branch, .. } => {
            assert!(else_branch.is_some());
        }
        _ => panic!("Expected if command"),
    }
}

#[test]
fn test_if_elif_else() {
    let cmd = parse("if a; then b; elif c; then d; elif e; then f; else g; fi");
    match &cmd {
        Command::If { elif_branches, else_branch, .. } => {
            assert_eq!(elif_branches.len(), 2);
            assert!(else_branch.is_some());
        }
        _ => panic!("Expected if command"),
    }
}

// --- For loop ---

#[test]
fn test_for_loop() {
    let cmd = parse("for x in a b c; do echo $x; done");
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
    let cmd = parse("while true; do echo loop; done");
    match &cmd {
        Command::Loop { kind: LoopKind::While, condition, body } => {
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
    let cmd = parse("until false; do echo loop; done");
    match &cmd {
        Command::Loop { kind: LoopKind::Until, condition, body } => {
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
    let cmd = parse("case $x in a) echo a;; b) echo b;; esac");
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
    let cmd = parse("case $x in a|b) echo ab;; esac");
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
    let cmd = parse("case $x in a) echo a;& b) echo b;; esac");
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
    let cmd = parse("case $x in a) echo a;;& b) echo b;; esac");
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms[0].terminator, CaseTerminator::Continue);
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_glob_pattern() {
    let cmd = parse("case $x in *) echo default;; esac");
    match &cmd {
        Command::Case { arms, .. } => {
            assert_eq!(arms.len(), 1);
            // The * is parsed as a glob
            assert!(arms[0].patterns[0].parts.iter().any(|p| matches!(p, WordPart::Glob(_))));
        }
        _ => panic!("Expected case command"),
    }
}

#[test]
fn test_case_empty_body() {
    let cmd = parse("case $x in a) ;; esac");
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
    let cmd = parse("function foo() { echo hello; }");
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
    let cmd = parse("function bar { echo hi; }");
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
    let cmd = parse("VAR=value");
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
    let cmd = parse("VAR=");
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
    let cmd = parse("VAR=value cmd arg");
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

// --- Redirections ---

#[test]
fn test_redirect_output() {
    let cmd = parse("echo hello > file.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
            assert!(sc.redirections[0].fd.is_none());
            match &sc.redirections[0].target {
                RedirectionTarget::File(w) => assert_eq!(w.to_str(), "file.txt"),
                _ => panic!("Expected file target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_input() {
    let cmd = parse("cat < input.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Input);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_append() {
    let cmd = parse("echo hello >> file.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Append);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_clobber() {
    let cmd = parse("echo hello >| file.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Clobber);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_dup_output() {
    let cmd = parse("cmd >&2");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::DupOutput);
            match &sc.redirections[0].target {
                RedirectionTarget::Fd(fd) => assert_eq!(*fd, 2),
                _ => panic!("Expected Fd target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_dup_input() {
    let cmd = parse("cmd <&3");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::DupInput);
            match &sc.redirections[0].target {
                RedirectionTarget::Fd(fd) => assert_eq!(*fd, 3),
                _ => panic!("Expected Fd target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_fd_prefix() {
    let cmd = parse("cmd 2>errors.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].fd, Some(2));
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_redirect_herestring() {
    let cmd = parse("cat <<< hello");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Herestring);
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Quoting ---

#[test]
fn test_single_quotes() {
    let cmd = parse("echo 'hello world'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            match &sc.words[1].parts[0] {
                WordPart::SingleQuoted(s) => assert_eq!(s, "hello world"),
                _ => panic!("Expected single quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_literal() {
    let cmd = parse(r#"echo "hello world""#);
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    assert_eq!(parts.len(), 1);
                    match &parts[0] {
                        WordPart::Literal(s) => assert_eq!(s, "hello world"),
                        _ => panic!("Expected literal inside double quotes"),
                    }
                }
                _ => panic!("Expected double quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_variable() {
    let cmd = parse(r#"echo "hello $name""#);
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    assert_eq!(parts.len(), 2);
                    assert!(matches!(&parts[0], WordPart::Literal(s) if s == "hello "));
                    assert!(matches!(&parts[1], WordPart::Parameter(s) if s == "name"));
                }
                _ => panic!("Expected double quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_command_sub() {
    let cmd = parse(r#"echo "today is $(date)""#);
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    assert!(parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(s) if s == "date")));
                }
                _ => panic!("Expected double quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_backtick() {
    let cmd = parse(r#"echo "today is `date`""#);
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    assert!(parts.iter().any(|p| matches!(p, WordPart::Backtick(s) if s == "date")));
                }
                _ => panic!("Expected double quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_ansi_c_quoting() {
    let cmd = parse("echo $'hello\\nworld'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::AnsiCQuoted(s) if s == "hello\nworld")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_backslash_escape() {
    let cmd = parse("echo hello\\ world");
    match &cmd {
        Command::Simple(sc) => {
            // backslash-space joins "hello" and "world" into a single word
            assert_eq!(sc.words.len(), 2);
            let text = sc.words[1].to_str();
            assert_eq!(text, "hello world");
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Variable expansion ---

#[test]
fn test_parameter() {
    let cmd = parse("echo $VAR");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Parameter(s) if s == "VAR")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_parameter_expansion() {
    let cmd = parse("echo ${VAR}");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::ParameterExpansion(s) if s == "VAR")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_special_variables() {
    for var in &["$@", "$?", "$$", "$!", "$#", "$*", "$-"] {
        let input = format!("echo {}", var);
        let cmd = parse(&input);
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].has_dynamic_parts(), "Expected dynamic for {}", var);
            }
            _ => panic!("Expected simple command for {}", var),
        }
    }
}

// --- Command substitution ---

#[test]
fn test_command_substitution() {
    let cmd = parse("echo $(whoami)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(s) if s == "whoami")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_backtick_substitution() {
    let cmd = parse("echo `whoami`");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Backtick(s) if s == "whoami")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_nested_command_substitution() {
    let cmd = parse("echo $(echo $(whoami))");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::CommandSubstitution(s) => assert_eq!(s, "echo $(whoami)"),
                _ => panic!("Expected command substitution"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Arithmetic ---

#[test]
fn test_arithmetic_expansion() {
    let cmd = parse("echo $((1 + 2))");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Arithmetic(s) if s == "1 + 2")));
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Globs ---

#[test]
fn test_glob_star() {
    let cmd = parse("echo *.txt");
    match &cmd {
        Command::Simple(sc) => {
            let word = &sc.words[1];
            assert!(word.parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "*")));
            assert!(word.parts.iter().any(|p| matches!(p, WordPart::Literal(s) if s == ".txt")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_glob_question() {
    let cmd = parse("echo file?.txt");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "?")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_glob_bracket() {
    let cmd = parse("echo [abc].txt");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "[abc]")));
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Brace expansion ---

#[test]
fn test_brace_expansion() {
    let cmd = parse("echo {a,b,c}");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::BraceExpansion(items) => {
                    assert_eq!(items, &["a", "b", "c"]);
                }
                _ => panic!("Expected brace expansion"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_brace_no_comma_is_literal() {
    let cmd = parse("echo {foo}");
    match &cmd {
        Command::Simple(sc) => {
            // Without comma, should be literal { and }
            let text = sc.words[1].to_str();
            assert_eq!(text, "{foo}");
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Process substitution ---

#[test]
fn test_process_substitution_input() {
    let cmd = parse("diff <(sort a) <(sort b)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 3); // diff, <(sort a), <(sort b)
            match &sc.words[1].parts[0] {
                WordPart::ProcessSubstitution { direction, command } => {
                    assert_eq!(*direction, ProcessDirection::Input);
                    assert_eq!(command, "sort a");
                }
                _ => panic!("Expected process substitution"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_process_substitution_output() {
    let cmd = parse("tee >(grep error)");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::ProcessSubstitution { direction, command } => {
                    assert_eq!(*direction, ProcessDirection::Output);
                    assert_eq!(command, "grep error");
                }
                _ => panic!("Expected process substitution"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Comments ---

#[test]
fn test_comment() {
    let cmd = parse("echo foo # this is a comment");
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
    let cmd = parse("# just a comment");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words.is_empty());
        }
        _ => panic!("Expected empty simple command"),
    }
}

// --- Word helper methods ---

#[test]
fn test_word_literal() {
    let w = Word::literal("hello");
    assert_eq!(w.parts.len(), 1);
    assert_eq!(w.to_str(), "hello");
    assert!(!w.has_dynamic_parts());
}

#[test]
fn test_word_to_str_various_parts() {
    let w = Word {
        parts: vec![
            WordPart::Literal("hello".to_string()),
            WordPart::SingleQuoted("world".to_string()),
        ],
    };
    assert_eq!(w.to_str(), "helloworld");
}

#[test]
fn test_word_to_str_brace_expansion() {
    let w = Word {
        parts: vec![WordPart::BraceExpansion(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ])],
    };
    assert_eq!(w.to_str(), "a,b,c");
}

#[test]
fn test_word_to_str_process_substitution() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "sort file".to_string(),
        }],
    };
    assert_eq!(w.to_str(), "sort file");
}

#[test]
fn test_word_has_dynamic_parts_parameter() {
    let w = Word {
        parts: vec![WordPart::Parameter("HOME".to_string())],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_command_sub() {
    let w = Word {
        parts: vec![WordPart::CommandSubstitution("date".to_string())],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_backtick() {
    let w = Word {
        parts: vec![WordPart::Backtick("date".to_string())],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic("1+1".to_string())],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_process_sub() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "cmd".to_string(),
        }],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_parameter_expansion() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansion("HOME".to_string())],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_in_double_quotes() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("hello ".to_string()),
            WordPart::Parameter("name".to_string()),
        ])],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_no_dynamic_parts_static() {
    let w = Word {
        parts: vec![
            WordPart::Literal("hello".to_string()),
            WordPart::SingleQuoted("world".to_string()),
            WordPart::Glob("*".to_string()),
            WordPart::BraceExpansion(vec!["a".to_string()]),
        ],
    };
    assert!(!w.has_dynamic_parts());
}

#[test]
fn test_word_to_str_double_quoted() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("hello ".to_string()),
            WordPart::Parameter("name".to_string()),
        ])],
    };
    assert_eq!(w.to_str(), "hello name");
}

// --- SimpleCommand helpers ---

#[test]
fn test_simple_command_name_none() {
    let sc = SimpleCommand {
        assignments: vec![],
        words: vec![],
        redirections: vec![],
    };
    assert_eq!(sc.command_name(), None);
}

#[test]
fn test_simple_command_args_empty() {
    let sc = SimpleCommand {
        assignments: vec![],
        words: vec![Word::literal("echo")],
        redirections: vec![],
    };
    assert!(sc.args().is_empty());
}

#[test]
fn test_simple_command_args_multiple() {
    let cmd = parse("echo a b c");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("echo"));
            assert_eq!(sc.args().len(), 3);
            assert_eq!(sc.args()[0].to_str(), "a");
            assert_eq!(sc.args()[1].to_str(), "b");
            assert_eq!(sc.args()[2].to_str(), "c");
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_simple_command_name_non_literal() {
    let sc = SimpleCommand {
        assignments: vec![],
        words: vec![Word {
            parts: vec![WordPart::Parameter("cmd".to_string())],
        }],
        redirections: vec![],
    };
    // command_name returns "" for non-literal first part
    assert_eq!(sc.command_name(), Some(""));
}

// --- extract_simple_commands ---

#[test]
fn test_extract_simple_commands_from_pipeline() {
    let cmd = parse("echo foo | grep bar | wc -l");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
    assert_eq!(scs[0].command_name(), Some("echo"));
    assert_eq!(scs[1].command_name(), Some("grep"));
    assert_eq!(scs[2].command_name(), Some("wc"));
}

#[test]
fn test_extract_simple_commands_from_and_or() {
    let cmd = parse("a && b || c");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
}

#[test]
fn test_extract_simple_commands_from_sequence() {
    let cmd = parse("a; b; c");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 3);
}

#[test]
fn test_extract_simple_commands_from_if() {
    let cmd = parse("if a; then b; elif c; then d; else e; fi");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 5); // a, b, c, d, e
}

#[test]
fn test_extract_simple_commands_from_for() {
    let cmd = parse("for x in a b; do echo $x; done");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1); // just the echo
}

#[test]
fn test_extract_simple_commands_from_while() {
    let cmd = parse("while true; do echo loop; done");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
    assert_eq!(scs[0].command_name(), Some("true"));
    assert_eq!(scs[1].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_until() {
    let cmd = parse("until false; do echo loop; done");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
    assert_eq!(scs[0].command_name(), Some("false"));
    assert_eq!(scs[1].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_case() {
    let cmd = parse("case $x in a) echo a;; b) echo b;; esac");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2);
}

#[test]
fn test_extract_simple_commands_from_function() {
    let cmd = parse("function foo() { echo hello; }");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
    assert_eq!(scs[0].command_name(), Some("echo"));
}

#[test]
fn test_extract_simple_commands_from_background() {
    let cmd = parse("sleep 10 &");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
    assert_eq!(scs[0].command_name(), Some("sleep"));
}

#[test]
fn test_extract_simple_commands_from_subshell() {
    let cmd = parse("(echo hello)");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
}

#[test]
fn test_extract_simple_commands_from_brace_group() {
    let cmd = parse("{ echo hello; }");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 1);
}

#[test]
fn test_extract_simple_commands_from_assignment() {
    let cmd = parse("FOO=bar");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 0); // assignments don't contain simple commands
}

// --- extract_all_words ---

#[test]
fn test_extract_all_words_simple() {
    let cmd = parse("echo hello world");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_with_redirections() {
    let cmd = parse("echo hello > file.txt");
    let words = extract_all_words(&cmd);
    // echo, hello, file.txt (redirect target)
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_with_assignment() {
    let cmd = parse("VAR=value cmd arg");
    let words = extract_all_words(&cmd);
    // assignment value + cmd + arg
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_standalone_assignment() {
    let cmd = parse("VAR=value");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1); // just the assignment value
}

#[test]
fn test_extract_all_words_from_for() {
    let cmd = parse("for x in a b c; do echo $x; done");
    let words = extract_all_words(&cmd);
    // a, b, c (for-loop words) + echo, $x (body words)
    assert_eq!(words.len(), 5);
}

#[test]
fn test_extract_all_words_from_case() {
    let cmd = parse("case $x in a) echo hello;; esac");
    let words = extract_all_words(&cmd);
    // $x (case word) + a (pattern) + echo, hello (body words)
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_from_pipeline() {
    let cmd = parse("echo a | grep b");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 4); // echo, a, grep, b
}

#[test]
fn test_extract_all_words_from_and_or() {
    let cmd = parse("cmd1 arg1 && cmd2 arg2");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_from_background() {
    let cmd = parse("echo hello &");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn test_extract_all_words_from_subshell() {
    let cmd = parse("(echo hello)");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn test_extract_all_words_from_if() {
    let cmd = parse("if true; then echo yes; else echo no; fi");
    let words = extract_all_words(&cmd);
    // true, echo, yes, echo, no
    assert_eq!(words.len(), 5);
}

#[test]
fn test_extract_all_words_from_while() {
    let cmd = parse("while true; do echo x; done");
    let words = extract_all_words(&cmd);
    // true, echo, x
    assert_eq!(words.len(), 3);
}

#[test]
fn test_extract_all_words_from_function() {
    let cmd = parse("function foo() { echo bar; }");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2); // echo, bar
}

// --- Complex / combined constructs ---

#[test]
fn test_pipeline_with_redirections() {
    let cmd = parse("cat < input.txt | sort > output.txt");
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
    let cmd = parse("if true; then for x in a b; do echo $x; done; fi");
    match &cmd {
        Command::If { then_branch, .. } => {
            match then_branch.as_ref() {
                Command::For { var, words, .. } => {
                    assert_eq!(var, "x");
                    assert_eq!(words.len(), 2);
                }
                _ => panic!("Expected for loop in then branch"),
            }
        }
        _ => panic!("Expected if command"),
    }
}

#[test]
fn test_newline_separated_commands() {
    // Multiple commands separated by semicolons produce a sequence
    let cmd = parse("echo a; echo b; echo c");
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
fn test_mixed_word_parts() {
    let cmd = parse("echo prefix${VAR}suffix");
    match &cmd {
        Command::Simple(sc) => {
            let word = &sc.words[1];
            assert!(word.parts.len() >= 3);
            assert!(matches!(&word.parts[0], WordPart::Literal(s) if s == "prefix"));
            assert!(matches!(&word.parts[1], WordPart::ParameterExpansion(s) if s == "VAR"));
            assert!(matches!(&word.parts[2], WordPart::Literal(s) if s == "suffix"));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_bare_dollar() {
    let cmd = parse("echo $");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Literal(s) if s == "$")));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_multiple_redirections() {
    let cmd = parse("cmd > out.txt 2>&1");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 2);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc() {
    let cmd = parse("cat << EOF");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Heredoc);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_strip() {
    let cmd = parse("cat <<- EOF");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::HeredocStrip);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_body_basic() {
    let cmd = parse("cat <<EOF\nhello\nworld\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "hello\nworld\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_body_strip_tabs() {
    let cmd = parse("cat <<-EOF\n\t\thello\n\t\tworld\n\t\tEOF");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "hello\nworld\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_single_quoted_delimiter() {
    let cmd = parse("cat <<'EOF'\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "hello\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_double_quoted_delimiter() {
    let cmd = parse("cat <<\"EOF\"\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "hello\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_backslash_escaped_delimiter() {
    let cmd = parse("cat <<\\EOF\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "hello\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_empty_body() {
    let cmd = parse("cat <<EOF\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_unterminated() {
    let cmd = parse("cat <<EOF\nhello\nworld");
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    // Graceful degradation: collects what's available
                    assert!(body.contains("hello"));
                    assert!(body.contains("world"));
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_with_command() {
    let cmd = parse("cat <<EOF\nline\nEOF");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("cat"));
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc(body) => {
                    assert_eq!(body, "line\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_escape() {
    let cmd = parse(r#"echo "hello\"world""#);
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    // Should have literal containing the escaped quote
                    let text: String = parts.iter().map(|p| match p {
                        WordPart::Literal(s) => s.clone(),
                        _ => String::new(),
                    }).collect();
                    assert!(text.contains("hello"));
                    assert!(text.contains("\""));
                    assert!(text.contains("world"));
                }
                _ => panic!("Expected double quoted"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_word_to_str_ansi_c() {
    let w = Word {
        parts: vec![WordPart::AnsiCQuoted("hello".to_string())],
    };
    assert_eq!(w.to_str(), "hello");
}

#[test]
fn test_word_to_str_glob() {
    let w = Word {
        parts: vec![WordPart::Glob("*".to_string())],
    };
    assert_eq!(w.to_str(), "*");
}

#[test]
fn test_has_dynamic_parts_double_quoted_static() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("static".to_string()),
        ])],
    };
    assert!(!w.has_dynamic_parts());
}

#[test]
fn test_has_dynamic_parts_ansi_c_is_static() {
    let w = Word {
        parts: vec![WordPart::AnsiCQuoted("hello".to_string())],
    };
    assert!(!w.has_dynamic_parts());
}

#[test]
fn test_extract_all_words_redirect_fd_target() {
    let cmd = parse("cmd >&2");
    let words = extract_all_words(&cmd);
    // cmd word only; Fd(2) is not a File target so not collected
    assert_eq!(words.len(), 1);
}

#[test]
fn test_case_with_empty_body_arm() {
    let cmd = parse("case $x in a) ;; b) echo b;; esac");
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
    let cmd = parse("case $x in a) ;; esac");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 0);
}

#[test]
fn test_if_without_else() {
    let cmd = parse("if true; then echo yes; fi");
    let scs = extract_simple_commands(&cmd);
    assert_eq!(scs.len(), 2); // true + echo
}

#[test]
fn test_extract_all_words_elif() {
    let cmd = parse("if a; then b; elif c; then d; fi");
    let words = extract_all_words(&cmd);
    // a, b, c, d
    assert_eq!(words.len(), 4);
}

#[test]
fn test_extract_all_words_until() {
    let cmd = parse("until false; do echo x; done");
    let words = extract_all_words(&cmd);
    // false, echo, x
    assert_eq!(words.len(), 3);
}

// -- static cat heredoc folding --

#[test]
fn cat_heredoc_single_quoted_is_literal() {
    let cmd = parse("echo $(cat <<'EOF'\nhello world\nEOF\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("hello world".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_heredoc_multiline_body() {
    let cmd = parse("echo $(cat <<'EOF'\nline one\nline two\nline three\nEOF\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("line one\nline two\nline three".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_heredoc_strip_tabs() {
    let cmd = parse("echo $(cat <<-'EOF'\n\t\thello\n\t\tEOF\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("hello".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_heredoc_unquoted_delim_folds() {
    let cmd = parse("echo $(cat <<EOF\nhello\nEOF\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("hello".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_heredoc_double_quoted_delim_folds() {
    let cmd = parse("echo $(cat <<\"EOF\"\nhello\nEOF\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("hello".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_with_file_arg_stays_dynamic() {
    let cmd = parse("echo $(cat /etc/hostname)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_herestring_static_folds() {
    let cmd = parse("echo $(cat <<< 'hello')");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("hello".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_herestring_dynamic_stays() {
    let cmd = parse("echo $(cat <<< $HOME)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn non_cat_command_sub_stays_dynamic() {
    let cmd = parse("echo $(whoami)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_with_output_redirect_stays_dynamic() {
    // cat with > redirect is not purely heredoc-fed
    let cmd = parse("echo $(cat <<'EOF'\nhello\nEOF\n > /tmp/out)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn bare_cat_stays_dynamic() {
    // bare cat with no redirections
    let cmd = parse("echo $(cat)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

// -- ANSI-C escape sequences ($'...') --

#[test]
fn ansi_c_standard_escapes() {
    let cmd = parse(r#"echo $'\\' $'\n' $'\t' $'\r' $'\a' $'\b' $'\e' $'\f' $'\v' $'\'' $'\"'"#);
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\\".into())]);
            assert_eq!(sc.words[2].parts, vec![WordPart::AnsiCQuoted("\n".into())]);
            assert_eq!(sc.words[3].parts, vec![WordPart::AnsiCQuoted("\t".into())]);
            assert_eq!(sc.words[4].parts, vec![WordPart::AnsiCQuoted("\r".into())]);
            assert_eq!(sc.words[5].parts, vec![WordPart::AnsiCQuoted("\x07".into())]);
            assert_eq!(sc.words[6].parts, vec![WordPart::AnsiCQuoted("\x08".into())]);
            assert_eq!(sc.words[7].parts, vec![WordPart::AnsiCQuoted("\x1B".into())]);
            assert_eq!(sc.words[8].parts, vec![WordPart::AnsiCQuoted("\x0C".into())]);
            assert_eq!(sc.words[9].parts, vec![WordPart::AnsiCQuoted("\x0B".into())]);
            assert_eq!(sc.words[10].parts, vec![WordPart::AnsiCQuoted("'".into())]);
            assert_eq!(sc.words[11].parts, vec![WordPart::AnsiCQuoted("\"".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_octal_escape() {
    let cmd = parse(r"echo $'\0101'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_bare_null() {
    let cmd = parse(r"echo $'\0'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\0".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_hex_escape() {
    let cmd = parse(r"echo $'\x41'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_unicode_escape() {
    let cmd = parse(r"echo $'\u0041'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_long_unicode_escape() {
    let cmd = parse(r"echo $'\U00000041'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_control_char() {
    let cmd = parse(r"echo $'\cA'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\x01".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_unknown_escape() {
    let cmd = parse(r"echo $'\z'");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("z".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_backslash_at_eof() {
    let cmd = parse("echo $'\\");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\\".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

// -- dynamic_parts descriptions --

#[test]
fn dynamic_parts_parameter_expansion() {
    let w = Word { parts: vec![WordPart::ParameterExpansion("HOME".into())] };
    assert_eq!(w.dynamic_parts(), vec!["${HOME}"]);
}

#[test]
fn dynamic_parts_backtick() {
    let w = Word { parts: vec![WordPart::Backtick("date".into())] };
    assert_eq!(w.dynamic_parts(), vec!["`date`"]);
}

#[test]
fn dynamic_parts_arithmetic() {
    let w = Word { parts: vec![WordPart::Arithmetic("1+2".into())] };
    assert_eq!(w.dynamic_parts(), vec!["$((1+2))"]);
}

#[test]
fn dynamic_parts_process_sub_input() {
    let w = Word { parts: vec![WordPart::ProcessSubstitution {
        direction: ProcessDirection::Input,
        command: "sort".into(),
    }] };
    assert_eq!(w.dynamic_parts(), vec!["<(sort)"]);
}

#[test]
fn dynamic_parts_process_sub_output() {
    let w = Word { parts: vec![WordPart::ProcessSubstitution {
        direction: ProcessDirection::Output,
        command: "tee log".into(),
    }] };
    assert_eq!(w.dynamic_parts(), vec![">(tee log)"]);
}

#[test]
fn dynamic_parts_in_double_quotes() {
    let w = Word { parts: vec![WordPart::DoubleQuoted(vec![
        WordPart::Literal("hi ".into()),
        WordPart::Parameter("USER".into()),
    ])] };
    assert_eq!(w.dynamic_parts(), vec!["$USER"]);
}

// -- to_str with various word parts --

#[test]
fn to_str_parameter_expansion() {
    let w = Word { parts: vec![WordPart::ParameterExpansion("HOME".into())] };
    assert_eq!(w.to_str(), "HOME");
}

#[test]
fn to_str_backtick() {
    let w = Word { parts: vec![WordPart::Backtick("date".into())] };
    assert_eq!(w.to_str(), "date");
}

#[test]
fn to_str_arithmetic() {
    let w = Word { parts: vec![WordPart::Arithmetic("1+2".into())] };
    assert_eq!(w.to_str(), "1+2");
}

// -- structural dynamic parts in control flow --

#[test]
fn structural_dynamic_case_arms() {
    use std::collections::HashMap;
    let cmd = parse("case $x in $pat) echo hi ;; esac");
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$x".to_string()));
    assert!(parts.contains(&"$pat".to_string()));
}

#[test]
fn structural_dynamic_elif_else() {
    use std::collections::HashMap;
    let cmd = parse("if true; then echo a; elif $cond; then echo b; else echo c; fi");
    let _parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
}

#[test]
fn structural_dynamic_function_body() {
    use std::collections::HashMap;
    let cmd = parse("function foo { for x in $items; do echo $x; done; }");
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$items".to_string()));
}

#[test]
fn structural_dynamic_redirected() {
    use std::collections::HashMap;
    let cmd = parse("for x in $items; do echo $x; done > /tmp/out");
    let parts = find_structural_dynamic_parts(&cmd, &HashMap::new());
    assert!(parts.contains(&"$items".to_string()));
}

// -- extract_simple_commands / extract_all_words edge cases --

#[test]
fn extract_simple_commands_from_redirected() {
    let cmd = parse("echo hello > /tmp/out");
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

#[test]
fn extract_simple_commands_from_compound_redirected() {
    let cmd = parse("{ echo hello; } > /tmp/out");
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

#[test]
fn extract_all_words_from_redirected() {
    let cmd = parse("echo hello > /tmp/out");
    let words = extract_all_words(&cmd);
    assert!(words.len() >= 3);
}

#[test]
fn extract_all_words_from_compound_redirected() {
    let cmd = parse("{ echo hello; } > /tmp/out");
    let words = extract_all_words(&cmd);
    assert!(words.len() >= 3);
}

#[test]
fn extract_all_words_from_compound_with_heredoc_redirect() {
    let cmd = parse("{ cat; } <<'EOF'\nhello\nEOF\n");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1);
}

#[test]
fn extract_all_words_from_compound_with_fd_redirect() {
    let cmd = parse("{ echo hi; } 2>&1");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 2);
}

#[test]
fn extract_all_words_from_standalone_assignment_value() {
    let cmd = parse("x=hello");
    let words = extract_all_words(&cmd);
    assert_eq!(words.len(), 1);
    assert_eq!(words[0].to_str(), "hello");
}

// -- newline / background in parse_list --

#[test]
fn newline_separated_commands_in_sequence() {
    let cmd = parse("echo a\necho b");
    match &cmd {
        Command::Sequence(cmds) => {
            assert_eq!(cmds.len(), 2);
        }
        _ => panic!("Expected sequence, got {:?}", cmd),
    }
}

#[test]
fn background_command_in_sequence() {
    let cmd = parse("sleep 1 & echo done");
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

// -- assignment with dynamic value --

#[test]
fn assignment_with_dynamic_value_parts() {
    let cmd = parse("x=hello$HOME");
    match &cmd {
        Command::Assignment(a) => {
            assert_eq!(a.name, "x");
            assert!(a.value.parts.len() >= 2);
            assert_eq!(a.value.parts[0], WordPart::Literal("hello".into()));
            assert!(matches!(&a.value.parts[1], WordPart::Parameter(s) if s == "HOME"));
        }
        _ => panic!("Expected assignment, got {:?}", cmd),
    }
}

// -- case with optional leading ( --

#[test]
fn case_with_leading_paren_in_pattern() {
    let cmd = parse("case x in (a) echo a ;; esac");
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
    let cmd = parse("case x in a) echo a\nesac");
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
    let cmd = parse("for ; do echo x; done");
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
    let cmd = parse("case\nin a) echo x ;; esac");
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
    let cmd = parse("function { echo x; }");
    match &cmd {
        Command::FunctionDef { name, .. } => {
            assert!(name.is_empty());
        }
        _ => panic!("Expected function def, got {:?}", cmd),
    }
}

// -- abbreviate helper --

#[test]
fn abbreviate_long_single_line() {
    let long = "a".repeat(80);
    let result = super::ast::abbreviate(&long);
    assert!(result.ends_with('…'));
    assert!(result.len() < 80);
}

#[test]
fn abbreviate_multiline() {
    let result = super::ast::abbreviate("first line\nsecond line");
    assert_eq!(result, "first line …");
}

#[test]
fn abbreviate_short_single_line() {
    assert_eq!(super::ast::abbreviate("hello"), "hello");
}

// -- unterminated brace expansion --

#[test]
fn unterminated_brace_is_literal() {
    let cmd = parse("echo {a,b");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].to_str(), "{a,b");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- comment before newline in lexer --

#[test]
fn comment_then_newline_then_command() {
    let cmd = parse("# comment\necho hello");
    let cmds = extract_simple_commands(&cmd);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command_name(), Some("echo"));
}

// -- unclosed arithmetic / command substitution --

#[test]
fn unclosed_arithmetic_at_eof() {
    let cmd = parse("echo $((1+2");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Arithmetic(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn unclosed_command_sub_at_eof() {
    let cmd = parse("echo $(whoami");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

// -- FD redirect that isn't a redirect --

#[test]
fn number_not_followed_by_redirect_is_arg() {
    let cmd = parse("echo 2foo");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            assert_eq!(sc.words[1].to_str(), "2foo");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- cat heredoc folding: combo cases --

#[test]
fn cat_heredoc_plus_herestring_concatenates() {
    let cmd = parse("echo $(cat <<'EOF'\nfirst\nEOF\n<<< 'second')");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("first\nsecond".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_multiple_heredocs_concatenates() {
    let cmd = parse("echo $(cat <<'A'\nfirst\nA\n<<'B'\nsecond\nB\n)");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("first\nsecond".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_no_input_stays_dynamic() {
    let cmd = parse("echo $(cat)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1]
                .parts
                .iter()
                .any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

// -- function definitions --

#[test]
fn function_definition_parsed() {
    let cmd = parse("greet() { echo hi; }");
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

// -- ANSI-C hex/unicode escapes with short sequences --

#[test]
fn ansic_hex_short_sequence() {
    let cmd = parse("echo $'\\x4G'");
    match &cmd {
        Command::Simple(sc) => {
            let s = sc.words[1].to_str();
            assert_eq!(s, "\x04G");
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansic_unicode_short_sequence() {
    let cmd = parse("echo $'\\u41G'");
    match &cmd {
        Command::Simple(sc) => {
            let s = sc.words[1].to_str();
            assert_eq!(s, "AG");
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansic_unicode_big_short_sequence() {
    let cmd = parse("echo $'\\U41G'");
    match &cmd {
        Command::Simple(sc) => {
            let s = sc.words[1].to_str();
            assert_eq!(s, "AG");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- fd duplication targets --

#[test]
fn redirect_dup_fd_with_dash() {
    let cmd = parse("echo hi 2>&-");
    match &cmd {
        Command::Redirected { redirections, .. } | Command::Simple(SimpleCommand { redirections, .. }) => {
            let has_fd_target = redirections.iter().any(|r| {
                matches!(&r.target, RedirectionTarget::Fd(_))
                    || matches!(&r.target, RedirectionTarget::File(w) if w.to_str() == "-")
            });
            assert!(has_fd_target, "Expected fd target in redirections: {:?}", redirections);
        }
        _ => panic!("Expected redirected command, got {:?}", cmd),
    }
}

#[test]
fn redirect_dup_fd_non_numeric() {
    let cmd = parse("echo hi >&foo");
    match &cmd {
        Command::Redirected { redirections, .. } => {
            assert!(redirections.iter().any(|r| {
                matches!(&r.target, RedirectionTarget::File(w) if w.to_str().contains("foo"))
                    || matches!(&r.target, RedirectionTarget::Fd(_))
            }));
        }
        _ => {
            // May be parsed differently; just ensure it doesn't panic
        }
    }
}

// -- try_fold_static_cat rejects non-Simple ASTs --

#[test]
fn compound_command_sub_stays_dynamic() {
    let cmd = parse("echo $(echo a; echo b)");
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1]
                .parts
                .iter()
                .any(|p| matches!(p, WordPart::CommandSubstitution(_))));
        }
        _ => panic!("Expected simple command"),
    }
}

// -- herestring-then-herestring separator --

#[test]
fn cat_two_herestrings_concatenates() {
    let cmd = parse("echo $(cat <<< 'first' <<< 'second')");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal("first\nsecond".to_string())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- Parameter expansion operator parsing --

#[test]
fn parse_param_length() {
    let cmd = parse("echo ${#VAR}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Length,
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_prefix_short() {
    let cmd = parse("echo ${VAR#*/}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripPrefix {
                        longest: false,
                        pattern: "*/".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_prefix_long() {
    let cmd = parse("echo ${VAR##*/}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripPrefix {
                        longest: true,
                        pattern: "*/".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_suffix_short() {
    let cmd = parse("echo ${VAR%.*}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripSuffix {
                        longest: false,
                        pattern: ".*".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_suffix_long() {
    let cmd = parse("echo ${VAR%%.*}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripSuffix {
                        longest: true,
                        pattern: ".*".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_first() {
    let cmd = parse("echo ${VAR/foo/bar}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: false,
                        pattern: "foo".into(),
                        replacement: "bar".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_all() {
    let cmd = parse("echo ${VAR//foo/bar}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: true,
                        pattern: "foo".into(),
                        replacement: "bar".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_empty_replacement() {
    let cmd = parse("echo ${VAR/foo}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: false,
                        pattern: "foo".into(),
                        replacement: String::new(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_default_colon() {
    let cmd = parse("echo ${VAR:-fallback}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Default {
                        colon: true,
                        value: "fallback".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_default_no_colon() {
    let cmd = parse("echo ${VAR-fallback}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Default {
                        colon: false,
                        value: "fallback".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_alternative_colon() {
    let cmd = parse("echo ${VAR:+set}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Alternative {
                        colon: true,
                        value: "set".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_error_colon() {
    let cmd = parse("echo ${VAR:?not set}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Error {
                        colon: true,
                        message: "not set".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_assign_colon() {
    let cmd = parse("echo ${VAR:=default}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Assign {
                        colon: true,
                        value: "default".into(),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_substring() {
    let cmd = parse("echo ${VAR:2:5}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Substring {
                        offset: "2".into(),
                        length: Some("5".into()),
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_substring_no_length() {
    let cmd = parse("echo ${VAR:3}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Substring {
                        offset: "3".into(),
                        length: None,
                    },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_uppercase_first() {
    let cmd = parse("echo ${VAR^}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Uppercase { all: false },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_uppercase_all() {
    let cmd = parse("echo ${VAR^^}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Uppercase { all: true },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_lowercase_first() {
    let cmd = parse("echo ${VAR,}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Lowercase { all: false },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_lowercase_all() {
    let cmd = parse("echo ${VAR,,}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Lowercase { all: true },
                },
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_simple_braced_unchanged() {
    let cmd = parse("echo ${VAR}");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::ParameterExpansion("VAR".into()),
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_op_in_double_quotes() {
    let cmd = parse(r#"echo "${HOME##*/}""#);
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![
                WordPart::DoubleQuoted(vec![
                    WordPart::ParameterExpansionOp {
                        name: "HOME".into(),
                        op: ParameterOperator::StripPrefix {
                            longest: true,
                            pattern: "*/".into(),
                        },
                    },
                ]),
            ]);
        }
        _ => panic!("Expected simple command"),
    }
}

// -- Glob matching --

#[test]
fn glob_match_literal() {
    assert!(glob_match("hello", "hello"));
    assert!(!glob_match("hello", "world"));
}

#[test]
fn glob_match_star() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*.txt", "file.txt"));
    assert!(!glob_match("*.txt", "file.rs"));
    assert!(glob_match("*/", "foo/"));
    assert!(glob_match("*/", "bar/baz/"));
}

#[test]
fn glob_match_question() {
    assert!(glob_match("?", "a"));
    assert!(!glob_match("?", ""));
    assert!(!glob_match("?", "ab"));
    assert!(glob_match("a?c", "abc"));
}

#[test]
fn glob_match_bracket() {
    assert!(glob_match("[abc]", "a"));
    assert!(glob_match("[abc]", "b"));
    assert!(!glob_match("[abc]", "d"));
    assert!(glob_match("[a-z]", "m"));
    assert!(!glob_match("[a-z]", "M"));
}

#[test]
fn glob_match_bracket_negate() {
    assert!(!glob_match("[!abc]", "a"));
    assert!(glob_match("[!abc]", "d"));
    assert!(glob_match("[^abc]", "d"));
}

#[test]
fn glob_match_empty() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
    assert!(glob_match("*", ""));
}

// -- Glob strip prefix --

#[test]
fn glob_strip_prefix_shortest() {
    assert_eq!(glob_strip_prefix("*/", "/usr/local/bin", false), "usr/local/bin");
}

#[test]
fn glob_strip_prefix_longest() {
    assert_eq!(glob_strip_prefix("*/", "/usr/local/bin", true), "bin");
}

#[test]
fn glob_strip_prefix_no_match() {
    assert_eq!(glob_strip_prefix("xyz", "hello", false), "hello");
}

// -- Glob strip suffix --

#[test]
fn glob_strip_suffix_shortest() {
    assert_eq!(glob_strip_suffix(".*", "file.tar.gz", false), "file.tar");
}

#[test]
fn glob_strip_suffix_longest() {
    assert_eq!(glob_strip_suffix(".*", "file.tar.gz", true), "file");
}

#[test]
fn glob_strip_suffix_no_match() {
    assert_eq!(glob_strip_suffix("xyz", "hello", false), "hello");
}

// -- Glob replace --

#[test]
fn glob_replace_first_only() {
    assert_eq!(glob_replace("o", "foobar", "0", false), "f0obar");
}

#[test]
fn glob_replace_all_occurrences() {
    assert_eq!(glob_replace("o", "foobar", "0", true), "f00bar");
}

#[test]
fn glob_replace_with_wildcard() {
    assert_eq!(glob_replace("*.txt", "hello.txt", "goodbye", false), "goodbye");
}

// -- Resolution of parameter expansion operators --

#[test]
fn resolve_param_length() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Length,
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "5");
    assert!(!resolved.has_dynamic_parts());
}

#[test]
fn resolve_param_strip_prefix() {
    let env = [("PATH".into(), "/usr/local/bin".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "PATH".into(),
        op: ParameterOperator::StripPrefix {
            longest: true,
            pattern: "*/".into(),
        },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "bin");
    assert!(!resolved.has_dynamic_parts());
}

#[test]
fn resolve_param_strip_suffix() {
    let env = [("FILE".into(), "archive.tar.gz".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "FILE".into(),
        op: ParameterOperator::StripSuffix {
            longest: false,
            pattern: ".*".into(),
        },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "archive.tar");
}

#[test]
fn resolve_param_replace() {
    let env = [("VAR".into(), "hello world".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Replace {
            all: false,
            pattern: "world".into(),
            replacement: "rust".into(),
        },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello rust");
}

#[test]
fn resolve_param_default_colon_empty() {
    let env = [("VAR".into(), String::new())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Default { colon: true, value: "fallback".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "fallback");
}

#[test]
fn resolve_param_default_colon_set() {
    let env = [("VAR".into(), "value".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Default { colon: true, value: "fallback".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_alternative_colon_set() {
    let env = [("VAR".into(), "value".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Alternative { colon: true, value: "alt".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "alt");
}

#[test]
fn resolve_param_alternative_colon_empty() {
    let env = [("VAR".into(), String::new())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Alternative { colon: true, value: "alt".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}

#[test]
fn resolve_param_substring() {
    let env = [("VAR".into(), "hello world".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Substring {
            offset: "6".into(),
            length: Some("5".into()),
        },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

#[test]
fn resolve_param_substring_no_length() {
    let env = [("VAR".into(), "hello world".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Substring {
            offset: "6".into(),
            length: None,
        },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

#[test]
fn resolve_param_uppercase_all() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Uppercase { all: true },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "HELLO");
}

#[test]
fn resolve_param_uppercase_first() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Uppercase { all: false },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "Hello");
}

#[test]
fn resolve_param_lowercase_all() {
    let env = [("VAR".into(), "HELLO".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Lowercase { all: true },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello");
}

#[test]
fn resolve_param_error_set() {
    let env = [("VAR".into(), "value".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Error { colon: true, message: "oops".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_assign_set() {
    let env = [("VAR".into(), "value".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Assign { colon: true, value: "default".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_unresolved_stays_dynamic() {
    let env = std::collections::HashMap::new();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "UNKNOWN".into(),
        op: ParameterOperator::StripPrefix {
            longest: true,
            pattern: "*/".into(),
        },
    }] };
    let resolved = w.resolve(&env);
    assert!(resolved.has_dynamic_parts());
    assert_eq!(resolved.dynamic_parts(), vec!["${UNKNOWN##*/}"]);
}

#[test]
fn resolve_param_op_in_double_quotes() {
    let env = [("HOME".into(), "/home/user".into())].into();
    let w = Word { parts: vec![WordPart::DoubleQuoted(vec![
        WordPart::ParameterExpansionOp {
            name: "HOME".into(),
            op: ParameterOperator::StripPrefix {
                longest: true,
                pattern: "*/".into(),
            },
        },
    ])] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "user");
    assert!(!resolved.has_dynamic_parts());
}

// -- Resolution: non-colon Default (variable is set) --

#[test]
fn resolve_param_default_no_colon_set() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Default { colon: false, value: "fallback".into() },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello");
}

// -- Resolution: Alternative with colon:false --

#[test]
fn resolve_param_alternative_no_colon_set() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Alternative { colon: false, value: "alt".into() },
    }] };
    let resolved = w.resolve(&env);
    // ${VAR+alt}: variable is set, so use alternative
    assert_eq!(resolved.to_str(), "alt");
}

// -- Resolution: Substring with negative offset --

#[test]
fn resolve_param_substring_negative_offset() {
    let env = [("VAR".into(), "hello world".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Substring { offset: "-5".into(), length: None },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

// -- Resolution: Uppercase first character only --

#[test]
fn resolve_param_uppercase_first_char() {
    let env = [("VAR".into(), "hello".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Uppercase { all: false },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "Hello");
}

#[test]
fn resolve_param_uppercase_first_empty() {
    let env = [("VAR".into(), "".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Uppercase { all: false },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}

// -- Resolution: Lowercase first character only --

#[test]
fn resolve_param_lowercase_first() {
    let env = [("VAR".into(), "HELLO".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Lowercase { all: false },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hELLO");
}

#[test]
fn resolve_param_lowercase_first_empty() {
    let env = [("VAR".into(), "".into())].into();
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "VAR".into(),
        op: ParameterOperator::Lowercase { all: false },
    }] };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}

// -- format_param_op coverage for uncovered arms --

#[test]
fn format_param_op_replace() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Replace { all: false, pattern: "a".into(), replacement: "b".into() }),
        "VAR/a/b"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Replace { all: true, pattern: "a".into(), replacement: "b".into() }),
        "VAR//a/b"
    );
}

#[test]
fn format_param_op_alternative() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Alternative { colon: true, value: "alt".into() }),
        "VAR:+alt"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Alternative { colon: false, value: "alt".into() }),
        "VAR+alt"
    );
}

#[test]
fn format_param_op_error() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Error { colon: true, message: "msg".into() }),
        "VAR:?msg"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Error { colon: false, message: "msg".into() }),
        "VAR?msg"
    );
}

#[test]
fn format_param_op_assign() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Assign { colon: true, value: "val".into() }),
        "VAR:=val"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Assign { colon: false, value: "val".into() }),
        "VAR=val"
    );
}

#[test]
fn format_param_op_substring() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Substring { offset: "2".into(), length: Some("3".into()) }),
        "VAR:2:3"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Substring { offset: "2".into(), length: None }),
        "VAR:2"
    );
}

#[test]
fn format_param_op_uppercase() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Uppercase { all: true }),
        "VAR^^"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Uppercase { all: false }),
        "VAR^"
    );
}

#[test]
fn format_param_op_lowercase() {
    use super::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Lowercase { all: true }),
        "VAR,,"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Lowercase { all: false }),
        "VAR,"
    );
}

// -- Glob: bracket with star backtrack --

#[test]
fn glob_bracket_no_match_backtracks_over_star() {
    // Pattern: *[0-9] should match "abc3" (star eats "abc", bracket matches "3")
    assert!(glob_match("*[0-9]", "abc3"));
    // But not "abcx"
    assert!(!glob_match("*[0-9]", "abcx"));
}

#[test]
fn glob_bracket_no_match_no_star_fails() {
    // [0-9] alone should not match "a"
    assert!(!glob_match("[0-9]", "a"));
}

#[test]
fn glob_malformed_bracket_treated_as_literal() {
    // "[abc" has no closing ] — treated as literal '['
    assert!(glob_match("[abc", "[abc"));
    assert!(!glob_match("[abc", "a"));
}

#[test]
fn glob_malformed_bracket_with_star_backtracks() {
    // "*[abc" — malformed bracket after star; '[' treated as literal
    assert!(glob_match("*[abc", "xyz[abc"));
}

#[test]
fn glob_malformed_bracket_no_star_mismatch() {
    // "[xyz" treated as literal '[' — doesn't match 'a'
    assert!(!glob_match("[xyz", "a"));
}

#[test]
fn glob_bracket_literal_close() {
    // []] matches ']'
    assert!(glob_match("[]]", "]"));
}

#[test]
fn glob_bracket_negate_close() {
    // [!]] matches anything except ']'
    assert!(glob_match("[!]]", "a"));
    assert!(!glob_match("[!]]", "]"));
}

// -- Lexer: non-colon parameter expansion operators --

#[test]
fn parse_param_expansion_no_colon_default() {
    let cmd = parse("echo ${VAR-fallback}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words.len(), 2);
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Default { colon: false, value: "fallback".into() },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_alternative() {
    let cmd = parse("echo ${VAR+alt}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Alternative { colon: false, value: "alt".into() },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_error() {
    let cmd = parse("echo ${VAR?msg}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Error { colon: false, message: "msg".into() },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_assign() {
    let cmd = parse("echo ${VAR=val}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Assign { colon: false, value: "val".into() },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_uppercase_single() {
    let cmd = parse("echo ${VAR^}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: false },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_uppercase_all() {
    let cmd = parse("echo ${VAR^^}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: true },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_lowercase_single() {
    let cmd = parse("echo ${VAR,}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Lowercase { all: false },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_lowercase_all() {
    let cmd = parse("echo ${VAR,,}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Lowercase { all: true },
        }]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_unknown_operator_fallback() {
    // An operator the lexer doesn't recognise falls back to flat ParameterExpansion
    let cmd = parse("echo ${VAR@Q}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansion("VAR@Q".into())]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_non_identifier_fallback() {
    // ${!VAR} — '!' is not a valid identifier start, falls back to flat
    let cmd = parse("echo ${!VAR}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansion("!VAR".into())]);
    } else {
        panic!("Expected simple command");
    }
}

// -- Lexer: empty redirect target produces empty word --

#[test]
fn parse_herestring_redirect_target() {
    // <<< with a word target
    let cmd = parse("cat <<< hello");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.command_name(), Some("cat"));
        assert_eq!(sc.redirections.len(), 1);
        assert_eq!(sc.redirections[0].kind, RedirectionKind::Herestring);
    } else {
        panic!("Expected simple command");
    }
}

// -- format_param_op: Length arm --

#[test]
fn format_param_op_length() {
    use super::ast::format_param_op;
    assert_eq!(format_param_op("VAR", &ParameterOperator::Length), "#VAR");
}

// -- dynamic_parts rendering for unresolved Length op --

#[test]
fn dynamic_parts_unresolved_length() {
    let w = Word { parts: vec![WordPart::ParameterExpansionOp {
        name: "UNSET".into(),
        op: ParameterOperator::Length,
    }] };
    assert!(w.has_dynamic_parts());
    assert_eq!(w.dynamic_parts(), vec!["${#UNSET}"]);
}

// -- Lexer: ${#@} where # is not followed by identifier+} --

#[test]
fn parse_param_expansion_hash_not_length() {
    // ${#} — '#' with no identifier is not length op, falls back to flat
    let cmd = parse("echo ${#}");
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansion("#".into())]);
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_hash_special() {
    // ${#*} — '#' followed by '*' (not a valid identifier), falls through
    let cmd = parse("echo ${#*}");
    if let Command::Simple(sc) = &cmd {
        // '#' not followed by ident+'}', so it restores pos and reads '#*' as flat
        assert_eq!(sc.words[1].parts, vec![WordPart::ParameterExpansion("#*".into())]);
    } else {
        panic!("Expected simple command");
    }
}

// --- [ as a command (test builtin) ---

#[test]
fn test_bracket_command() {
    // `[` is a shell builtin command, not a glob bracket expression.
    let cmd = parse("[ -f foo ]");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("["));
            assert_eq!(sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(), vec!["-f", "foo", "]"]);
        }
        _ => panic!("Expected simple command, got: {cmd:?}"),
    }
}

#[test]
fn test_bracket_command_in_if() {
    // `[ -f foo ]` used as a condition in an if statement.
    let cmd = parse("if [ -f foo ]; then echo yes; fi");
    match &cmd {
        Command::If { condition, .. } => {
            // The condition should contain the `[` command
            match condition.as_ref() {
                Command::Simple(sc) => {
                    assert_eq!(sc.command_name(), Some("["));
                    assert_eq!(sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(), vec!["-f", "foo", "]"]);
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
    let cmd = parse("[[ -f foo ]]");
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("[["));
            assert_eq!(sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(), vec!["-f", "foo", "]]"]);
        }
        _ => panic!("Expected simple command, got: {cmd:?}"),
    }
}

#[test]
fn test_double_bracket_in_if() {
    let cmd = parse("if [[ -f foo ]]; then echo yes; fi");
    match &cmd {
        Command::If { condition, .. } => {
            match condition.as_ref() {
                Command::Simple(sc) => {
                    assert_eq!(sc.command_name(), Some("[["));
                    assert_eq!(sc.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(), vec!["-f", "foo", "]]"]);
                }
                other => panic!("Expected simple command as condition, got: {other:?}"),
            }
        }
        _ => panic!("Expected if command, got: {cmd:?}"),
    }
}

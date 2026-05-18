use crate::*;

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
            span: Span { start: 0, end: 0 },
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
        parts: vec![WordPart::CommandSubstitution {
            source: "date".to_string(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_backtick() {
    let w = Word {
        parts: vec![WordPart::Backtick {
            source: "date".to_string(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic {
            source: "1+1".to_string(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.has_dynamic_parts());
}

#[test]
fn test_word_has_dynamic_parts_process_sub() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "cmd".to_string(),
            span: Span { start: 0, end: 0 },
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
        span: Span { start: 0, end: 0 },
    };
    assert_eq!(sc.command_name(), None);
}

#[test]
fn test_simple_command_args_empty() {
    let sc = SimpleCommand {
        assignments: vec![],
        words: vec![Word::literal("echo")],
        redirections: vec![],
        span: Span { start: 0, end: 0 },
    };
    assert!(sc.args().is_empty());
}

#[test]
fn test_simple_command_args_multiple() {
    let cmd = parse("echo a b c").into_command();
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
        span: Span { start: 0, end: 0 },
    };
    // command_name returns "" for non-literal first part
    assert_eq!(sc.command_name(), Some(""));
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
        parts: vec![WordPart::DoubleQuoted(vec![WordPart::Literal(
            "static".to_string(),
        )])],
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

// -- dynamic_parts descriptions --

#[test]
fn dynamic_parts_parameter_expansion() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansion("HOME".into())],
    };
    assert_eq!(w.dynamic_parts(), vec!["${HOME}"]);
}

#[test]
fn dynamic_parts_backtick() {
    let w = Word {
        parts: vec![WordPart::Backtick {
            source: "date".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.dynamic_parts(), vec!["`date`"]);
}

#[test]
fn dynamic_parts_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic {
            source: "1+2".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.dynamic_parts(), vec!["$((1+2))"]);
}

#[test]
fn dynamic_parts_process_sub_input() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "sort".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.dynamic_parts(), vec!["<(sort)"]);
}

#[test]
fn dynamic_parts_process_sub_output() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Output,
            command: "tee log".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.dynamic_parts(), vec![">(tee log)"]);
}

#[test]
fn dynamic_parts_in_double_quotes() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("hi ".into()),
            WordPart::Parameter("USER".into()),
        ])],
    };
    assert_eq!(w.dynamic_parts(), vec!["$USER"]);
}

// -- to_str with various word parts --

#[test]
fn to_str_parameter_expansion() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansion("HOME".into())],
    };
    assert_eq!(w.to_str(), "HOME");
}

#[test]
fn to_str_backtick() {
    let w = Word {
        parts: vec![WordPart::Backtick {
            source: "date".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.to_str(), "date");
}

#[test]
fn to_str_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic {
            source: "1+2".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.to_str(), "1+2");
}

// -- dynamic_parts rendering for unresolved Length op --

#[test]
fn dynamic_parts_unresolved_length() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "UNSET".into(),
            op: ParameterOperator::Length,
        }],
    };
    assert!(w.has_dynamic_parts());
    assert_eq!(w.dynamic_parts(), vec!["${#UNSET}"]);
}

// -- is_dynamic (broader than has_dynamic_parts: includes Glob and Opaque) --

#[test]
fn is_dynamic_literal_false() {
    assert!(!Word::literal("echo").is_dynamic());
}

#[test]
fn is_dynamic_single_quoted_false() {
    let w = Word {
        parts: vec![WordPart::SingleQuoted("echo".into())],
    };
    assert!(!w.is_dynamic());
}

#[test]
fn is_dynamic_ansi_c_quoted_false() {
    let w = Word {
        parts: vec![WordPart::AnsiCQuoted("echo".into())],
    };
    assert!(!w.is_dynamic());
}

#[test]
fn is_dynamic_brace_expansion_false() {
    let w = Word {
        parts: vec![WordPart::BraceExpansion(vec!["a".into(), "b".into()])],
    };
    assert!(!w.is_dynamic());
}

#[test]
fn is_dynamic_double_quoted_static_false() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![WordPart::Literal(
            "echo".into(),
        )])],
    };
    assert!(!w.is_dynamic());
}

#[test]
fn is_dynamic_parameter_true() {
    let w = Word {
        parts: vec![WordPart::Parameter("CMD".into())],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_parameter_expansion_true() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansion("CMD".into())],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_parameter_expansion_op_true() {
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "CMD".into(),
            op: ParameterOperator::Length,
        }],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_command_substitution_true() {
    let w = Word {
        parts: vec![WordPart::CommandSubstitution {
            source: "which python".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_backtick_true() {
    let w = Word {
        parts: vec![WordPart::Backtick {
            source: "which python".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_arithmetic_true() {
    let w = Word {
        parts: vec![WordPart::Arithmetic {
            source: "1+1".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_glob_true() {
    let w = Word {
        parts: vec![WordPart::Glob("*".into())],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_opaque_true() {
    let w = Word {
        parts: vec![WordPart::Opaque("???".into())],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_process_substitution_true() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "sort file".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert!(w.is_dynamic());
}

#[test]
fn is_dynamic_double_quoted_with_parameter_true() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("pre".into()),
            WordPart::Parameter("CMD".into()),
        ])],
    };
    assert!(w.is_dynamic());
}

// -- extract_embedded_commands --

#[test]
fn extract_embedded_commands_literal_empty() {
    let w = Word::literal("hello");
    assert!(w.extract_embedded_commands().is_empty());
}

#[test]
fn extract_embedded_commands_command_substitution() {
    let w = Word {
        parts: vec![WordPart::CommandSubstitution {
            source: "rm -rf /".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["rm -rf /"]);
}

#[test]
fn extract_embedded_commands_backtick() {
    let w = Word {
        parts: vec![WordPart::Backtick {
            source: "date".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["date"]);
}

#[test]
fn extract_embedded_commands_process_sub_input() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "ls /a".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["ls /a"]);
}

#[test]
fn extract_embedded_commands_process_sub_output() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Output,
            command: "tee log".into(),
            span: Span { start: 0, end: 0 },
        }],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["tee log"]);
}

#[test]
fn extract_embedded_commands_in_double_quotes() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::Literal("hi ".into()),
            WordPart::CommandSubstitution {
                source: "whoami".into(),
                span: Span { start: 0, end: 0 },
            },
        ])],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["whoami"]);
}

#[test]
fn extract_embedded_commands_multiple() {
    let w = Word {
        parts: vec![
            WordPart::CommandSubstitution {
                source: "cmd1".into(),
                span: Span { start: 0, end: 0 },
            },
            WordPart::Literal("-".into()),
            WordPart::Backtick {
                source: "cmd2".into(),
                span: Span { start: 0, end: 0 },
            },
        ],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["cmd1", "cmd2"]);
}

#[test]
fn extract_embedded_commands_parameter_not_included() {
    let w = Word {
        parts: vec![WordPart::Parameter("VAR".into())],
    };
    assert!(w.extract_embedded_commands().is_empty());
}

#[test]
fn extract_embedded_commands_nested_double_quote() {
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::CommandSubstitution {
                source: "echo $(rm /)".into(),
                span: Span { start: 0, end: 0 },
            },
        ])],
    };
    assert_eq!(w.extract_embedded_commands(), vec!["echo $(rm /)"]);
}

// -- POSIX line continuation (`\<NL>`) --

#[test]
fn line_continuation_after_operator() {
    let cmd = parse("mkdir -p foo && \\\n   ls bar").into_command();
    let Command::And(left, right) = &cmd else {
        panic!("expected And, got {cmd:?}");
    };
    let Command::Simple(left_sc) = left.as_ref() else {
        panic!("expected simple command on left");
    };
    assert_eq!(left_sc.command_name(), Some("mkdir"));
    let Command::Simple(right_sc) = right.as_ref() else {
        panic!("expected simple command on right");
    };
    assert_eq!(right_sc.command_name(), Some("ls"));
    assert_eq!(right_sc.args().len(), 1);
    assert_eq!(right_sc.args()[0].to_str(), "bar");
    // No `\n` should appear in any literal part of any word.
    for w in &right_sc.words {
        for p in &w.parts {
            if let WordPart::Literal(s) = p {
                assert!(
                    !s.contains('\n'),
                    "unexpected newline in literal part: {s:?}"
                );
            }
        }
    }
}

#[test]
fn line_continuation_mid_word() {
    let cmd = parse("ec\\\nho hi").into_command();
    let Command::Simple(sc) = &cmd else {
        panic!("expected simple command, got {cmd:?}");
    };
    assert_eq!(sc.command_name(), Some("echo"));
    assert_eq!(sc.args().len(), 1);
    assert_eq!(sc.args()[0].to_str(), "hi");
}

#[test]
fn line_continuation_inside_double_quotes() {
    let cmd = parse("echo \"foo\\\nbar\"").into_command();
    let Command::Simple(sc) = &cmd else {
        panic!("expected simple command, got {cmd:?}");
    };
    assert_eq!(sc.command_name(), Some("echo"));
    assert_eq!(sc.args().len(), 1);
    assert_eq!(sc.args()[0].to_str(), "foobar");
}

#[test]
fn backslash_newline_inside_single_quotes_is_literal() {
    let cmd = parse("echo 'foo\\\nbar'").into_command();
    let Command::Simple(sc) = &cmd else {
        panic!("expected simple command, got {cmd:?}");
    };
    assert_eq!(sc.args().len(), 1);
    // Single quotes preserve the backslash and newline verbatim.
    assert_eq!(sc.args()[0].to_str(), "foo\\\nbar");
}

#[test]
fn backslash_newline_inside_quoted_heredoc_is_literal() {
    let cmd = parse("cat <<'EOF'\nfoo\\\nbar\nEOF\n").into_command();
    let Command::Simple(sc) = &cmd else {
        panic!("expected simple command, got {cmd:?}");
    };
    assert_eq!(sc.command_name(), Some("cat"));
    assert_eq!(sc.redirections.len(), 1);
    let RedirectionTarget::Heredoc(body) = &sc.redirections[0].target else {
        panic!("expected heredoc body");
    };
    assert!(
        body.contains("foo\\\nbar"),
        "heredoc body should preserve backslash-newline verbatim: {body:?}"
    );
}

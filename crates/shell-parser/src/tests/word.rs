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
        parts: vec![WordPart::Backtick("date".into())],
    };
    assert_eq!(w.dynamic_parts(), vec!["`date`"]);
}

#[test]
fn dynamic_parts_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic("1+2".into())],
    };
    assert_eq!(w.dynamic_parts(), vec!["$((1+2))"]);
}

#[test]
fn dynamic_parts_process_sub_input() {
    let w = Word {
        parts: vec![WordPart::ProcessSubstitution {
            direction: ProcessDirection::Input,
            command: "sort".into(),
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
        parts: vec![WordPart::Backtick("date".into())],
    };
    assert_eq!(w.to_str(), "date");
}

#[test]
fn to_str_arithmetic() {
    let w = Word {
        parts: vec![WordPart::Arithmetic("1+2".into())],
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

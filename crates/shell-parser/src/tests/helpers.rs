use crate::*;

// -- abbreviate helper --

#[test]
fn abbreviate_long_single_line() {
    let long = "a".repeat(80);
    let result = crate::ast::abbreviate(&long);
    assert!(result.ends_with('…'));
    assert!(result.len() < 80);
}

#[test]
fn abbreviate_multiline() {
    let result = crate::ast::abbreviate("first line\nsecond line");
    assert_eq!(result, "first line …");
}

#[test]
fn abbreviate_short_single_line() {
    assert_eq!(crate::ast::abbreviate("hello"), "hello");
}

// -- static cat heredoc folding --

#[test]
fn cat_heredoc_single_quoted_is_literal() {
    let cmd = parse("echo $(cat <<'EOF'\nhello world\nEOF\n)").into_command();
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
    let cmd = parse("echo $(cat <<'EOF'\nline one\nline two\nline three\nEOF\n)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::Literal(
                    "line one\nline two\nline three".to_string()
                )]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_heredoc_strip_tabs() {
    let cmd = parse("echo $(cat <<-'EOF'\n\t\thello\n\t\tEOF\n)").into_command();
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
    let cmd = parse("echo $(cat <<EOF\nhello\nEOF\n)").into_command();
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
    let cmd = parse("echo $(cat <<\"EOF\"\nhello\nEOF\n)").into_command();
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
    let cmd = parse("echo $(cat /etc/hostname)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_herestring_static_folds() {
    let cmd = parse("echo $(cat <<< 'hello')").into_command();
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
    let cmd = parse("echo $(cat <<< $HOME)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn non_cat_command_sub_stays_dynamic() {
    let cmd = parse("echo $(whoami)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn cat_with_output_redirect_stays_dynamic() {
    // cat with > redirect is not purely heredoc-fed
    let cmd = parse("echo $(cat <<'EOF'\nhello\nEOF\n > /tmp/out)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn bare_cat_stays_dynamic() {
    // bare cat with no redirections
    let cmd = parse("echo $(cat)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- cat heredoc folding: combo cases --

#[test]
fn cat_heredoc_plus_herestring_concatenates() {
    let cmd = parse("echo $(cat <<'EOF'\nfirst\nEOF\n<<< 'second')").into_command();
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
    let cmd = parse("echo $(cat <<'A'\nfirst\nA\n<<'B'\nsecond\nB\n)").into_command();
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
    let cmd = parse("echo $(cat)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution(_)))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- herestring-then-herestring separator --

#[test]
fn cat_two_herestrings_concatenates() {
    let cmd = parse("echo $(cat <<< 'first' <<< 'second')").into_command();
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

// -- format_param_op coverage for uncovered arms --

#[test]
fn format_param_op_replace() {
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Replace {
                all: false,
                pattern: "a".into(),
                replacement: "b".into()
            }
        ),
        "VAR/a/b"
    );
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Replace {
                all: true,
                pattern: "a".into(),
                replacement: "b".into()
            }
        ),
        "VAR//a/b"
    );
}

#[test]
fn format_param_op_alternative() {
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Alternative {
                colon: true,
                value: "alt".into()
            }
        ),
        "VAR:+alt"
    );
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Alternative {
                colon: false,
                value: "alt".into()
            }
        ),
        "VAR+alt"
    );
}

#[test]
fn format_param_op_error() {
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Error {
                colon: true,
                message: "msg".into()
            }
        ),
        "VAR:?msg"
    );
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Error {
                colon: false,
                message: "msg".into()
            }
        ),
        "VAR?msg"
    );
}

#[test]
fn format_param_op_assign() {
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Assign {
                colon: true,
                value: "val".into()
            }
        ),
        "VAR:=val"
    );
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Assign {
                colon: false,
                value: "val".into()
            }
        ),
        "VAR=val"
    );
}

#[test]
fn format_param_op_substring() {
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Substring {
                offset: "2".into(),
                length: Some("3".into())
            }
        ),
        "VAR:2:3"
    );
    assert_eq!(
        format_param_op(
            "VAR",
            &ParameterOperator::Substring {
                offset: "2".into(),
                length: None
            }
        ),
        "VAR:2"
    );
}

#[test]
fn format_param_op_uppercase() {
    use crate::ast::format_param_op;
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
    use crate::ast::format_param_op;
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Lowercase { all: true }),
        "VAR,,"
    );
    assert_eq!(
        format_param_op("VAR", &ParameterOperator::Lowercase { all: false }),
        "VAR,"
    );
}

// -- format_param_op: Length arm --

#[test]
fn format_param_op_length() {
    use crate::ast::format_param_op;
    assert_eq!(format_param_op("VAR", &ParameterOperator::Length), "#VAR");
}

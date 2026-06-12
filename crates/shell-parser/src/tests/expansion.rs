use crate::*;

// --- Quoting ---

#[test]
fn test_single_quotes() {
    let cmd = parse("echo 'hello world'").into_command();
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
    let cmd = parse(r#"echo "hello world""#).into_command();
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
    let cmd = parse(r#"echo "hello $name""#).into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::DoubleQuoted(parts) => {
                assert_eq!(parts.len(), 2);
                assert!(matches!(&parts[0], WordPart::Literal(s) if s == "hello "));
                assert!(matches!(&parts[1], WordPart::Parameter(s) if s == "name"));
            }
            _ => panic!("Expected double quoted"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_command_sub() {
    let cmd = parse(r#"echo "today is $(date)""#).into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::DoubleQuoted(parts) => {
                assert!(parts.iter().any(
                    |p| matches!(p, WordPart::CommandSubstitution { source: s, .. } if s == "date")
                ));
            }
            _ => panic!("Expected double quoted"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_double_quotes_with_backtick() {
    let cmd = parse(r#"echo "today is `date`""#).into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::DoubleQuoted(parts) => {
                assert!(
                    parts
                        .iter()
                        .any(|p| matches!(p, WordPart::Backtick { source: s, .. } if s == "date"))
                );
            }
            _ => panic!("Expected double quoted"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_ansi_c_quoting() {
    let cmd = parse("echo $'hello\\nworld'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::AnsiCQuoted(s) if s == "hello\nworld"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_backslash_escape() {
    let cmd = parse("echo hello\\ world").into_command();
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

#[test]
fn test_double_quotes_with_escape() {
    let cmd = parse(r#"echo "hello\"world""#).into_command();
    match &cmd {
        Command::Simple(sc) => {
            match &sc.words[1].parts[0] {
                WordPart::DoubleQuoted(parts) => {
                    // Should have literal containing the escaped quote
                    let text: String = parts
                        .iter()
                        .map(|p| match p {
                            WordPart::Literal(s) => s.clone(),
                            _ => String::new(),
                        })
                        .collect();
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

// --- Variable expansion ---

#[test]
fn test_parameter() {
    let cmd = parse("echo $VAR").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Parameter(s) if s == "VAR"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_parameter_expansion() {
    let cmd = parse("echo ${VAR}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::ParameterExpansion(s) if s == "VAR"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_special_variables() {
    for var in &["$@", "$?", "$$", "$!", "$#", "$*", "$-"] {
        let input = format!("echo {}", var);
        let cmd = parse(&input).into_command();
        match &cmd {
            Command::Simple(sc) => {
                assert!(
                    sc.words[1].has_dynamic_parts(),
                    "Expected dynamic for {}",
                    var
                );
            }
            _ => panic!("Expected simple command for {}", var),
        }
    }
}

// --- Command substitution ---

#[test]
fn test_command_substitution() {
    let cmd = parse("echo $(whoami)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(sc.words[1].parts.iter().any(
                |p| matches!(p, WordPart::CommandSubstitution { source: s, .. } if s == "whoami")
            ));
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_backtick_substitution() {
    let cmd = parse("echo `whoami`").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Backtick { source: s, .. } if s == "whoami"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_nested_command_substitution() {
    let cmd = parse("echo $(echo $(whoami))").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::CommandSubstitution { source: s, .. } => assert_eq!(s, "echo $(whoami)"),
            _ => panic!("Expected command substitution"),
        },
        _ => panic!("Expected simple command"),
    }
}

// -- try_fold_static_cat rejects non-Simple ASTs --

#[test]
fn compound_command_sub_stays_dynamic() {
    let cmd = parse("echo $(echo a; echo b)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution { .. }))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Arithmetic ---

#[test]
fn test_arithmetic_expansion() {
    let cmd = parse("echo $((1 + 2))").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Arithmetic { source: s, .. } if s == "1 + 2"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Process substitution ---

#[test]
fn test_process_substitution_input() {
    let cmd = parse("diff <(sort a) <(sort b)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 3); // diff, <(sort a), <(sort b)
            match &sc.words[1].parts[0] {
                WordPart::ProcessSubstitution {
                    direction, command, ..
                } => {
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
    let cmd = parse("tee >(grep error)").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::ProcessSubstitution {
                direction, command, ..
            } => {
                assert_eq!(*direction, ProcessDirection::Output);
                assert_eq!(command, "grep error");
            }
            _ => panic!("Expected process substitution"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_process_substitution_argument_captures_inner_command() {
    let cmd = parse("cat <(rm -rf /danger)").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            match &sc.words[1].parts[0] {
                WordPart::ProcessSubstitution {
                    direction, command, ..
                } => {
                    assert_eq!(*direction, ProcessDirection::Input);
                    assert_eq!(command, "rm -rf /danger");
                }
                _ => panic!("Expected process substitution"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_process_substitution_nested_balances_parens() {
    // The inner `$(date)` parens must not terminate the procsub early.
    let cmd = parse("cat <(grep $(date) f)").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::ProcessSubstitution { command, .. } => {
                assert_eq!(command, "grep $(date) f");
            }
            _ => panic!("Expected process substitution"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_output_process_substitution_as_redirect_target() {
    // `exec > >(cmd)` — output redirect whose target is an output procsub.
    let cmd = parse("exec > >(tee log)").into_command();
    let sc = match &cmd {
        Command::Simple(sc) => sc,
        _ => panic!("Expected simple command, got {cmd:?}"),
    };
    assert_eq!(sc.redirections.len(), 1);
    match &sc.redirections[0].target {
        RedirectionTarget::File(w) => match &w.parts[0] {
            WordPart::ProcessSubstitution {
                direction, command, ..
            } => {
                assert_eq!(*direction, ProcessDirection::Output);
                assert_eq!(command, "tee log");
            }
            other => panic!("Expected process substitution target, got {other:?}"),
        },
        other => panic!("Expected file target, got {other:?}"),
    }
}

#[test]
fn test_fd_prefixed_redirect_to_process_substitution() {
    // `cmd 2> >(tee err)` — fd prefix routes through the same target reader.
    let cmd = parse("cmd 2> >(tee err)").into_command();
    let sc = match &cmd {
        Command::Simple(sc) => sc,
        _ => panic!("Expected simple command, got {cmd:?}"),
    };
    assert_eq!(sc.redirections.len(), 1);
    assert_eq!(sc.redirections[0].fd, Some(2));
    match &sc.redirections[0].target {
        RedirectionTarget::File(w) => assert!(
            matches!(
                &w.parts[0],
                WordPart::ProcessSubstitution { command, .. } if command == "tee err"
            ),
            "Expected process substitution target, got {:?}",
            w.parts
        ),
        other => panic!("Expected file target, got {other:?}"),
    }
}

#[test]
fn test_redirect_of_subshell_is_not_process_substitution() {
    // `< (` (space before the paren) is NOT a process substitution — it is
    // a redirect whose target is a stray subshell. The parser must not
    // fabricate a procsub; the unplaceable `(` surfaces as an Error so the
    // decision floors to :ask.
    let result = parse("cat < (find .)");
    let has_procsub = crate::extract_simple_commands(&result.command)
        .iter()
        .flat_map(|sc| {
            sc.words
                .iter()
                .chain(sc.redirections.iter().filter_map(|r| match &r.target {
                    RedirectionTarget::File(w) => Some(w),
                    _ => None,
                }))
        })
        .any(|w| {
            w.parts
                .iter()
                .any(|p| matches!(p, WordPart::ProcessSubstitution { .. }))
        });
    assert!(!has_procsub, "`< (` must not parse as process substitution");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.severity == crate::diagnostic::Severity::Error),
        "expected Error diagnostic for stray subshell target, got: {:?}",
        result.diagnostics
    );
}

#[test]
fn test_process_substitution_redirect_target_captures_inner_command() {
    let result = parse("while read x; do :; done < <(rm -rf /danger)");
    // No Error-severity diagnostic: the procsub target parses cleanly.
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.severity == crate::diagnostic::Severity::Error),
        "unexpected Error diagnostic: {:?}",
        result.diagnostics
    );
    // The redirect target carries the process substitution's inner command.
    let cmd = result.into_command();
    let redirs = match &cmd {
        Command::Redirected { redirections, .. } => redirections,
        _ => panic!("Expected redirected command, got {cmd:?}"),
    };
    assert_eq!(redirs.len(), 1);
    match &redirs[0].target {
        RedirectionTarget::File(w) => match &w.parts[0] {
            WordPart::ProcessSubstitution {
                direction, command, ..
            } => {
                assert_eq!(*direction, ProcessDirection::Input);
                assert_eq!(command, "rm -rf /danger");
            }
            other => panic!("Expected process substitution target, got {other:?}"),
        },
        other => panic!("Expected file target, got {other:?}"),
    }
}

// --- Brace expansion ---

#[test]
fn test_brace_expansion() {
    let cmd = parse("echo {a,b,c}").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.words[1].parts[0] {
            WordPart::BraceExpansion(items) => {
                assert_eq!(items, &["a", "b", "c"]);
            }
            _ => panic!("Expected brace expansion"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_brace_no_comma_is_literal() {
    let cmd = parse("echo {foo}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            // Without comma, should be literal { and }
            let text = sc.words[1].to_str();
            assert_eq!(text, "{foo}");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- unterminated brace expansion --

#[test]
fn unterminated_brace_is_literal() {
    let cmd = parse("echo {a,b").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].to_str(), "{a,b");
        }
        _ => panic!("Expected simple command"),
    }
}

// --- Mixed parts ---

#[test]
fn test_mixed_word_parts() {
    let cmd = parse("echo prefix${VAR}suffix").into_command();
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

// --- Bare dollar ---

#[test]
fn test_bare_dollar() {
    let cmd = parse("echo $").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Literal(s) if s == "$"))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- unclosed arithmetic / command substitution --

#[test]
fn unclosed_arithmetic_at_eof() {
    let cmd = parse("echo $((1+2").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::Arithmetic { .. }))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn unclosed_command_sub_at_eof() {
    let cmd = parse("echo $(whoami").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert!(
                sc.words[1]
                    .parts
                    .iter()
                    .any(|p| matches!(p, WordPart::CommandSubstitution { .. }))
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- FD redirect that isn't a redirect --

#[test]
fn number_not_followed_by_redirect_is_arg() {
    let cmd = parse("echo 2foo").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words.len(), 2);
            assert_eq!(sc.words[1].to_str(), "2foo");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- assignment with dynamic value --

#[test]
fn assignment_with_dynamic_value_parts() {
    let cmd = parse("x=hello$HOME").into_command();
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

// -- ANSI-C escape sequences ($'...') --

#[test]
fn ansi_c_standard_escapes() {
    let cmd = parse(r#"echo $'\\' $'\n' $'\t' $'\r' $'\a' $'\b' $'\e' $'\f' $'\v' $'\'' $'\"'"#)
        .into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\\".into())]);
            assert_eq!(sc.words[2].parts, vec![WordPart::AnsiCQuoted("\n".into())]);
            assert_eq!(sc.words[3].parts, vec![WordPart::AnsiCQuoted("\t".into())]);
            assert_eq!(sc.words[4].parts, vec![WordPart::AnsiCQuoted("\r".into())]);
            assert_eq!(
                sc.words[5].parts,
                vec![WordPart::AnsiCQuoted("\x07".into())]
            );
            assert_eq!(
                sc.words[6].parts,
                vec![WordPart::AnsiCQuoted("\x08".into())]
            );
            assert_eq!(
                sc.words[7].parts,
                vec![WordPart::AnsiCQuoted("\x1B".into())]
            );
            assert_eq!(
                sc.words[8].parts,
                vec![WordPart::AnsiCQuoted("\x0C".into())]
            );
            assert_eq!(
                sc.words[9].parts,
                vec![WordPart::AnsiCQuoted("\x0B".into())]
            );
            assert_eq!(sc.words[10].parts, vec![WordPart::AnsiCQuoted("'".into())]);
            assert_eq!(sc.words[11].parts, vec![WordPart::AnsiCQuoted("\"".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_octal_escape() {
    let cmd = parse(r"echo $'\0101'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_bare_null() {
    let cmd = parse(r"echo $'\0'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\0".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_hex_escape() {
    let cmd = parse(r"echo $'\x41'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_unicode_escape() {
    let cmd = parse(r"echo $'\u0041'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_long_unicode_escape() {
    let cmd = parse(r"echo $'\U00000041'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("A".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_control_char() {
    let cmd = parse(r"echo $'\cA'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::AnsiCQuoted("\x01".into())]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_unknown_escape() {
    let cmd = parse(r"echo $'\z'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("z".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn ansi_c_backslash_at_eof() {
    let cmd = parse("echo $'\\").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.words[1].parts, vec![WordPart::AnsiCQuoted("\\".into())]);
        }
        _ => panic!("Expected simple command"),
    }
}

// -- ANSI-C hex/unicode escapes with short sequences --

#[test]
fn ansic_hex_short_sequence() {
    let cmd = parse("echo $'\\x4G'").into_command();
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
    let cmd = parse("echo $'\\u41G'").into_command();
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
    let cmd = parse("echo $'\\U41G'").into_command();
    match &cmd {
        Command::Simple(sc) => {
            let s = sc.words[1].to_str();
            assert_eq!(s, "AG");
        }
        _ => panic!("Expected simple command"),
    }
}

// -- Parameter expansion operator parsing --

#[test]
fn parse_param_length() {
    let cmd = parse("echo ${#VAR}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Length,
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_prefix_short() {
    let cmd = parse("echo ${VAR#*/}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripPrefix {
                        longest: false,
                        pattern: "*/".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_prefix_long() {
    let cmd = parse("echo ${VAR##*/}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripPrefix {
                        longest: true,
                        pattern: "*/".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_suffix_short() {
    let cmd = parse("echo ${VAR%.*}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripSuffix {
                        longest: false,
                        pattern: ".*".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_strip_suffix_long() {
    let cmd = parse("echo ${VAR%%.*}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::StripSuffix {
                        longest: true,
                        pattern: ".*".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_first() {
    let cmd = parse("echo ${VAR/foo/bar}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: false,
                        pattern: "foo".into(),
                        replacement: "bar".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_all() {
    let cmd = parse("echo ${VAR//foo/bar}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: true,
                        pattern: "foo".into(),
                        replacement: "bar".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_replace_empty_replacement() {
    let cmd = parse("echo ${VAR/foo}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Replace {
                        all: false,
                        pattern: "foo".into(),
                        replacement: String::new(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_default_colon() {
    let cmd = parse("echo ${VAR:-fallback}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Default {
                        colon: true,
                        value: "fallback".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_default_no_colon() {
    let cmd = parse("echo ${VAR-fallback}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Default {
                        colon: false,
                        value: "fallback".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_alternative_colon() {
    let cmd = parse("echo ${VAR:+set}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Alternative {
                        colon: true,
                        value: "set".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_error_colon() {
    let cmd = parse("echo ${VAR:?not set}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Error {
                        colon: true,
                        message: "not set".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_assign_colon() {
    let cmd = parse("echo ${VAR:=default}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Assign {
                        colon: true,
                        value: "default".into(),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_substring() {
    let cmd = parse("echo ${VAR:2:5}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Substring {
                        offset: "2".into(),
                        length: Some("5".into()),
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_substring_no_length() {
    let cmd = parse("echo ${VAR:3}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Substring {
                        offset: "3".into(),
                        length: None,
                    },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_uppercase_first() {
    let cmd = parse("echo ${VAR^}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Uppercase { all: false },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_uppercase_all() {
    let cmd = parse("echo ${VAR^^}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Uppercase { all: true },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_lowercase_first() {
    let cmd = parse("echo ${VAR,}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Lowercase { all: false },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_lowercase_all() {
    let cmd = parse("echo ${VAR,,}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansionOp {
                    name: "VAR".into(),
                    op: ParameterOperator::Lowercase { all: true },
                },]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_simple_braced_unchanged() {
    let cmd = parse("echo ${VAR}").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::ParameterExpansion("VAR".into()),]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn parse_param_op_in_double_quotes() {
    let cmd = parse(r#"echo "${HOME##*/}""#).into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.words[1].parts,
                vec![WordPart::DoubleQuoted(vec![
                    WordPart::ParameterExpansionOp {
                        name: "HOME".into(),
                        op: ParameterOperator::StripPrefix {
                            longest: true,
                            pattern: "*/".into(),
                        },
                    },
                ]),]
            );
        }
        _ => panic!("Expected simple command"),
    }
}

// -- Lexer: non-colon parameter expansion operators --

#[test]
fn parse_param_expansion_no_colon_default() {
    let cmd = parse("echo ${VAR-fallback}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.words.len(), 2);
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Default {
                    colon: false,
                    value: "fallback".into()
                },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_alternative() {
    let cmd = parse("echo ${VAR+alt}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Alternative {
                    colon: false,
                    value: "alt".into()
                },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_error() {
    let cmd = parse("echo ${VAR?msg}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Error {
                    colon: false,
                    message: "msg".into()
                },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_no_colon_assign() {
    let cmd = parse("echo ${VAR=val}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Assign {
                    colon: false,
                    value: "val".into()
                },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_uppercase_single() {
    let cmd = parse("echo ${VAR^}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Uppercase { all: false },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_uppercase_all() {
    let cmd = parse("echo ${VAR^^}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Uppercase { all: true },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_lowercase_single() {
    let cmd = parse("echo ${VAR,}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Lowercase { all: false },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_lowercase_all() {
    let cmd = parse("echo ${VAR,,}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansionOp {
                name: "VAR".into(),
                op: ParameterOperator::Lowercase { all: true },
            }]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_unknown_operator_fallback() {
    // An operator the lexer doesn't recognise falls back to flat ParameterExpansion
    let cmd = parse("echo ${VAR@Q}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansion("VAR@Q".into())]
        );
    } else {
        panic!("Expected simple command");
    }
}

#[test]
fn parse_param_expansion_non_identifier_fallback() {
    // ${!VAR} — '!' is not a valid identifier start, falls back to flat
    let cmd = parse("echo ${!VAR}").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(
            sc.words[1].parts,
            vec![WordPart::ParameterExpansion("!VAR".into())]
        );
    } else {
        panic!("Expected simple command");
    }
}

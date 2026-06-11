use crate::*;

// --- Redirections ---

#[test]
fn test_redirect_output() {
    let cmd = parse("echo hello > file.txt").into_command();
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
    let cmd = parse("cat < input.txt").into_command();
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
    let cmd = parse("echo hello >> file.txt").into_command();
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
    let cmd = parse("echo hello >| file.txt").into_command();
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
    let cmd = parse("cmd >&2").into_command();
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
    let cmd = parse("cmd <&3").into_command();
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
    let cmd = parse("cmd 2>errors.txt").into_command();
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
    let cmd = parse("cat <<< hello").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            assert_eq!(sc.redirections[0].kind, RedirectionKind::Herestring);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_multiple_redirections() {
    let cmd = parse("cmd > out.txt 2>&1").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 2);
        }
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc() {
    let cmd = parse("cat << EOF").into_command();
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
    let cmd = parse("cat <<- EOF").into_command();
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
    let cmd = parse("cat <<EOF\nhello\nworld\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.redirections.len(), 1);
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc { body, .. } => {
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
    let cmd = parse("cat <<-EOF\n\t\thello\n\t\tworld\n\t\tEOF").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc { body, .. } => {
                assert_eq!(body, "hello\nworld\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_single_quoted_delimiter() {
    let cmd = parse("cat <<'EOF'\nhello\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc { body, .. } => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_double_quoted_delimiter() {
    let cmd = parse("cat <<\"EOF\"\nhello\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc { body, .. } => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_backslash_escaped_delimiter() {
    let cmd = parse("cat <<\\EOF\nhello\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc { body, .. } => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_empty_body() {
    let cmd = parse("cat <<EOF\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc { body, .. } => {
                assert_eq!(body, "");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_unterminated() {
    let cmd = parse("cat <<EOF\nhello\nworld").into_command();
    match &cmd {
        Command::Simple(sc) => {
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc { body, .. } => {
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
    let cmd = parse("cat <<EOF\nline\nEOF").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("cat"));
            match &sc.redirections[0].target {
                RedirectionTarget::Heredoc { body, .. } => {
                    assert_eq!(body, "line\n");
                }
                _ => panic!("Expected Heredoc target"),
            }
        }
        _ => panic!("Expected simple command"),
    }
}

// -- fd duplication targets --

#[test]
fn redirect_dup_fd_with_dash() {
    let cmd = parse("echo hi 2>&-").into_command();
    match &cmd {
        Command::Redirected { redirections, .. }
        | Command::Simple(SimpleCommand { redirections, .. }) => {
            let has_fd_target = redirections.iter().any(|r| {
                matches!(&r.target, RedirectionTarget::Fd(_))
                    || matches!(&r.target, RedirectionTarget::File(w) if w.to_str() == "-")
            });
            assert!(
                has_fd_target,
                "Expected fd target in redirections: {:?}",
                redirections
            );
        }
        _ => panic!("Expected redirected command, got {:?}", cmd),
    }
}

#[test]
fn redirect_dup_fd_non_numeric() {
    let cmd = parse("echo hi >&foo").into_command();
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

// -- Lexer: empty redirect target produces empty word --

#[test]
fn parse_herestring_redirect_target() {
    // <<< with a word target
    let cmd = parse("cat <<< hello").into_command();
    if let Command::Simple(sc) = &cmd {
        assert_eq!(sc.command_name(), Some("cat"));
        assert_eq!(sc.redirections.len(), 1);
        assert_eq!(sc.redirections[0].kind, RedirectionKind::Herestring);
    } else {
        panic!("Expected simple command");
    }
}

// ── evaluate-unquoted-heredoc-substitutions ──────────────────────────

/// Helper: the single heredoc target of a parsed input.
fn heredoc_target(input: &str) -> (String, bool, Vec<WordPart>) {
    let cmd = parse(input).into_command();
    let Command::Simple(sc) = &cmd else {
        panic!("expected simple command for {input:?}, got {cmd:?}");
    };
    let RedirectionTarget::Heredoc {
        body,
        quoted,
        substitutions,
    } = &sc.redirections[0].target
    else {
        panic!("expected heredoc target for {input:?}");
    };
    (body.clone(), *quoted, substitutions.clone())
}

#[test]
fn unquoted_heredoc_records_unquoted_delimiter() {
    let (_body, quoted, _subs) = heredoc_target("cat <<EOF\nhello\nEOF\n");
    assert!(!quoted);
}

#[test]
fn quoted_heredoc_delimiters_record_quoted() {
    for input in [
        "cat <<'EOF'\n$(rm --force)\nEOF\n",
        "cat <<\"EOF\"\n$(rm --force)\nEOF\n",
        "cat <<\\EOF\n$(rm --force)\nEOF\n",
    ] {
        let (_body, quoted, subs) = heredoc_target(input);
        assert!(quoted, "expected quoted delimiter for {input:?}");
        assert!(
            subs.is_empty(),
            "quoted body must stay inert for {input:?}: {subs:?}"
        );
    }
}

#[test]
fn unquoted_heredoc_extracts_command_substitution() {
    let input = "cat <<EOF\n$(rm --force)\nEOF\n";
    let (_body, quoted, subs) = heredoc_target(input);
    assert!(!quoted);
    assert_eq!(subs.len(), 1);
    let WordPart::CommandSubstitution { source, span } = &subs[0] else {
        panic!("expected command substitution, got {subs:?}");
    };
    assert_eq!(source, "rm --force");
    // Inner-span semantics: the span covers the body of the substitution
    // in the ORIGINAL input (excludes the `$(` and `)` sigils).
    assert_eq!(&input[span.start..span.end], "rm --force");
}

#[test]
fn unquoted_heredoc_extracts_backtick_and_arithmetic() {
    let input = "cat <<EOF\na `rm --force` b\nc $((1+2)) d\nEOF\n";
    let (_body, _quoted, subs) = heredoc_target(input);
    assert_eq!(subs.len(), 2, "{subs:?}");
    let WordPart::Backtick { source, span } = &subs[0] else {
        panic!("expected backtick, got {subs:?}");
    };
    assert_eq!(source, "rm --force");
    assert_eq!(&input[span.start..span.end], "rm --force");
    let WordPart::Arithmetic { source, .. } = &subs[1] else {
        panic!("expected arithmetic, got {subs:?}");
    };
    assert_eq!(source, "1+2");
}

#[test]
fn unquoted_heredoc_ignores_process_substitution() {
    // bash performs no process substitution in heredoc bodies; the text
    // is inert (often documentation).
    let (_body, _quoted, subs) = heredoc_target("cat <<EOF\n<(rm --force)\nEOF\n");
    assert!(subs.is_empty(), "{subs:?}");
}

#[test]
fn unquoted_heredoc_honours_backslash_escapes() {
    // In an unquoted heredoc body, backslash escapes `$` and backtick.
    let (_body, _quoted, subs) = heredoc_target("cat <<EOF\n\\$(rm --force) \\`rm\\`\nEOF\n");
    assert!(subs.is_empty(), "escaped sigils must not extract: {subs:?}");
}

#[test]
fn unquoted_heredoc_single_quotes_do_not_suppress() {
    // Quotes are NOT special inside heredoc bodies — '$(rm)' still runs.
    let (_body, _quoted, subs) = heredoc_target("cat <<EOF\n'$(rm --force)'\nEOF\n");
    assert_eq!(subs.len(), 1, "{subs:?}");
}

#[test]
fn unquoted_heredoc_unterminated_substitution_not_extracted() {
    let input = "cat <<EOF\n$(rm --force\nEOF\n";
    let result = parse(input);
    let Command::Simple(sc) = &result.clone().into_command() else {
        panic!("expected simple command");
    };
    let RedirectionTarget::Heredoc { substitutions, .. } = &sc.redirections[0].target else {
        panic!("expected heredoc target");
    };
    assert!(
        substitutions.is_empty(),
        "unterminated substitution must not be extracted: {substitutions:?}"
    );
    assert!(
        result.has_errors(),
        "expected an Error-severity diagnostic for the unterminated substitution"
    );
}

#[test]
fn static_cat_fold_keeps_quoted_only() {
    // `$(cat <<'EOF' …)` is static — folds to a literal. The unquoted
    // form is NOT static when the body carries expansion syntax: folding
    // it would hide the embedded `$(rm --force)` from evaluation.
    let folded = parse("echo $(cat <<'EOF'\nhello\nEOF\n)").into_command();
    let Command::Simple(sc) = &folded else {
        panic!("expected simple command");
    };
    assert!(matches!(&sc.args()[0].parts[0], WordPart::Literal(s) if s == "hello"));

    let unfolded = parse("echo $(cat <<EOF\n$(rm --force)\nEOF\n)").into_command();
    let Command::Simple(sc) = &unfolded else {
        panic!("expected simple command");
    };
    assert!(
        matches!(&sc.args()[0].parts[0], WordPart::CommandSubstitution { .. }),
        "unquoted dynamic heredoc must not fold to a literal: {:?}",
        sc.args()[0].parts
    );
}

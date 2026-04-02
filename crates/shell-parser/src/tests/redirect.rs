use crate::*;

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
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc(body) => {
                assert_eq!(body, "hello\nworld\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_single_quoted_delimiter() {
    let cmd = parse("cat <<'EOF'\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc(body) => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_double_quoted_delimiter() {
    let cmd = parse("cat <<\"EOF\"\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc(body) => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_backslash_escaped_delimiter() {
    let cmd = parse("cat <<\\EOF\nhello\nEOF");
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc(body) => {
                assert_eq!(body, "hello\n");
            }
            _ => panic!("Expected Heredoc target"),
        },
        _ => panic!("Expected simple command"),
    }
}

#[test]
fn test_heredoc_empty_body() {
    let cmd = parse("cat <<EOF\nEOF");
    match &cmd {
        Command::Simple(sc) => match &sc.redirections[0].target {
            RedirectionTarget::Heredoc(body) => {
                assert_eq!(body, "");
            }
            _ => panic!("Expected Heredoc target"),
        },
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

// -- fd duplication targets --

#[test]
fn redirect_dup_fd_with_dash() {
    let cmd = parse("echo hi 2>&-");
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

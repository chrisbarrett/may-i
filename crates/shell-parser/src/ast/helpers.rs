use super::*;

/// If a command substitution contains `cat` fed only by static heredocs
/// (and/or herestrings), the output is fully determined at parse time.
/// Parse the inner command and return the concatenated body if static.
pub(crate) fn try_fold_static_cat(cmd: &str) -> Option<String> {
    let result = crate::parse(cmd);
    // Unwrap a Redirected wrapping a Simple command
    // parse() of `cat <<'DELIM'...` always yields Command::Simple
    // because parse_simple_command consumes all redirect tokens inline.
    // Command::Redirected only wraps compound commands (if/for/while/…).
    let sc = match &result.command {
        Command::Simple(sc) => sc,
        _ => return None,
    };
    check_cat_heredoc(sc)
}

fn check_cat_heredoc(sc: &SimpleCommand) -> Option<String> {
    // Must be `cat` with no extra arguments
    if sc.command_name() != Some("cat") {
        return None;
    }
    if sc.words.len() > 1 {
        return None; // cat has file arguments — not purely heredoc-fed
    }
    if sc.assignments.is_empty() && sc.redirections.is_empty() {
        return None; // bare `cat` with no input
    }

    // All redirections must be heredocs/herestrings (stdin), and there
    // must be at least one.
    let mut body = String::new();
    let mut has_heredoc = false;
    for redir in &sc.redirections {
        match (&redir.kind, &redir.target) {
            (
                RedirectionKind::Heredoc | RedirectionKind::HeredocStrip,
                RedirectionTarget::Heredoc {
                    body: text, quoted, ..
                },
            ) => {
                // Only a quoted heredoc is static: an unquoted body is
                // subject to parameter/command/arithmetic expansion, so
                // its parse-time text is not the runtime output and
                // folding it would hide embedded commands from
                // evaluation. Bail unless the unquoted body provably
                // contains no expansion syntax at all.
                if !quoted && (text.contains('$') || text.contains('`') || text.contains('\\')) {
                    return None;
                }
                // Parser heredoc bodies always end with '\n', so the
                // previous body (if any) already has a trailing newline
                // and no explicit separator is needed.
                assert!(
                    body.is_empty() || body.ends_with('\n'),
                    "heredoc body missing trailing newline: {body:?}"
                );
                body.push_str(text);
                has_heredoc = true;
            }
            (RedirectionKind::Herestring, RedirectionTarget::File(word)) => {
                if word.has_dynamic_parts() {
                    return None;
                }
                if !body.is_empty() && !body.ends_with('\n') {
                    body.push('\n');
                }
                body.push_str(&word.to_str());
                has_heredoc = true;
            }
            _ => return None, // other redirections (file input, output) — bail
        }
    }

    // Unreachable: the early return on empty redirections guarantees we
    // entered the loop, and every non-bailing arm sets has_heredoc.
    assert!(
        has_heredoc,
        "unreachable: loop exited without setting has_heredoc"
    );

    // The parser's heredoc body may include a trailing newline;
    // strip it to match the actual output of `cat`.
    let body = body.strip_suffix('\n').unwrap_or(&body).to_string();
    Some(body)
}

/// Abbreviate a string for use in error messages. Multi-line content is
/// reduced to the first line with "…" appended; long single lines are
/// truncated at 60 chars.
pub(crate) fn abbreviate(s: &str) -> String {
    let first_line = s.lines().next().unwrap_or(s);
    let is_multiline = s.contains('\n');
    if first_line.len() > 60 {
        format!("{}…", &first_line[..60])
    } else if is_multiline {
        format!("{first_line} …")
    } else {
        first_line.to_string()
    }
}

/// Format a subscripted array expansion back to shell syntax (without `${`
/// and `}`): `arr[@]`, `arr[0]`, `#arr[@]`. The subscript word is flattened
/// with [`Word::to_str`] (a dynamic subscript like `$i` round-trips through
/// its source form via that flattening's existing handling).
pub(crate) fn format_array_expansion(name: &str, subscript: &Subscript, length: bool) -> String {
    let sub = match subscript {
        Subscript::Index(w) => w.to_str(),
        Subscript::All => "@".to_string(),
        Subscript::Star => "*".to_string(),
    };
    let hash = if length { "#" } else { "" };
    format!("{hash}{name}[{sub}]")
}

/// Format a parameter expansion operator back to shell syntax (without `${` and `}`).
pub(crate) fn format_param_op(name: &str, op: &ParameterOperator) -> String {
    match op {
        ParameterOperator::Length => format!("#{name}"),
        ParameterOperator::StripPrefix { longest, pattern } => {
            if *longest {
                format!("{name}##{pattern}")
            } else {
                format!("{name}#{pattern}")
            }
        }
        ParameterOperator::StripSuffix { longest, pattern } => {
            if *longest {
                format!("{name}%%{pattern}")
            } else {
                format!("{name}%{pattern}")
            }
        }
        ParameterOperator::Replace {
            all,
            pattern,
            replacement,
        } => {
            if *all {
                format!("{name}//{pattern}/{replacement}")
            } else {
                format!("{name}/{pattern}/{replacement}")
            }
        }
        ParameterOperator::Default { colon, value } => {
            if *colon {
                format!("{name}:-{value}")
            } else {
                format!("{name}-{value}")
            }
        }
        ParameterOperator::Alternative { colon, value } => {
            if *colon {
                format!("{name}:+{value}")
            } else {
                format!("{name}+{value}")
            }
        }
        ParameterOperator::Error { colon, message } => {
            if *colon {
                format!("{name}:?{message}")
            } else {
                format!("{name}?{message}")
            }
        }
        ParameterOperator::Assign { colon, value } => {
            if *colon {
                format!("{name}:={value}")
            } else {
                format!("{name}={value}")
            }
        }
        ParameterOperator::Substring { offset, length } => match length {
            Some(len) => format!("{name}:{offset}:{len}"),
            None => format!("{name}:{offset}"),
        },
        ParameterOperator::Uppercase { all } => {
            if *all {
                format!("{name}^^")
            } else {
                format!("{name}^")
            }
        }
        ParameterOperator::Lowercase { all } => {
            if *all {
                format!("{name},,")
            } else {
                format!("{name},")
            }
        }
    }
}

use may_i_shell_parser::{Command, SimpleCommand, extract_simple_commands};

/// Byte range in the original input string covered by an `EvalUnit`.
pub(super) type Span = (usize, usize);

/// A unit of evaluation extracted from an AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalUnit {
    /// A simple command extracted from the AST.
    SimpleCommand {
        command: String,
        args: Vec<String>,
        span: Span,
    },
    /// An embedded command found in a word part (substitution).
    EmbeddedCommand { source: String, span: Span },
    /// A command with a dynamic name that cannot be resolved.
    DynamicCommand { reason: String, span: Span },
}

impl EvalUnit {
    /// Byte range in the original input covered by this unit.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            EvalUnit::SimpleCommand { span, .. }
            | EvalUnit::EmbeddedCommand { span, .. }
            | EvalUnit::DynamicCommand { span, .. } => *span,
        }
    }
}

/// Walk the AST and extract all evaluation units, computing byte ranges
/// against `input` (which the AST was parsed from).
///
/// For each simple command in the AST:
/// - If the command name is dynamic, emit `DynamicCommand`
/// - Otherwise, emit `SimpleCommand`
/// - For all word parts across command name and arguments, extract embedded
///   commands (substitutions) as `EmbeddedCommand`, with spans located by
///   scanning the simple command's source slice in word-part order.
pub fn decompose(cmd: &Command, input: &str) -> Vec<EvalUnit> {
    let simple_commands = extract_simple_commands(cmd);
    let mut units = Vec::new();

    for sc in simple_commands {
        decompose_simple_command(sc, input, &mut units);
    }

    units
}

fn decompose_simple_command(sc: &SimpleCommand, input: &str, units: &mut Vec<EvalUnit>) {
    let sc_span = (sc.span.start, sc.span.end);

    // Check for assignment-only commands (no words)
    if sc.words.is_empty() {
        for assignment in &sc.assignments {
            let sources: Vec<String> = assignment
                .value
                .extract_embedded_commands()
                .into_iter()
                .map(str::to_string)
                .collect();
            push_embedded_units(input, sc_span, &sources, units);
        }
        return;
    }

    let first_word = &sc.words[0];

    if first_word.is_dynamic() {
        units.push(EvalUnit::DynamicCommand {
            reason: format!(
                "dynamic command name: {}",
                first_word.dynamic_parts().join(", ")
            ),
            span: sc_span,
        });
    } else {
        let command = first_word.to_str();
        let args: Vec<String> = sc.words[1..].iter().map(|w| w.to_str()).collect();
        units.push(EvalUnit::SimpleCommand {
            command,
            args,
            span: sc_span,
        });
    }

    let sources: Vec<String> = sc
        .words
        .iter()
        .flat_map(|w| {
            w.extract_embedded_commands()
                .into_iter()
                .map(str::to_string)
        })
        .collect();
    push_embedded_units(input, sc_span, &sources, units);
}

fn push_embedded_units(input: &str, sc_span: Span, sources: &[String], units: &mut Vec<EvalUnit>) {
    if sources.is_empty() {
        return;
    }
    let scope = &input[sc_span.0..sc_span.1];
    let spans = find_substitution_spans(scope);
    // Pair each parsed embedded source with the next scanner-found span. The
    // scanner walks the simple command's source slice top-to-bottom, the
    // parser collects embeds in the same word-by-word order, so positions and
    // sources line up by index.
    for (idx, source) in sources.iter().enumerate() {
        let span = spans
            .get(idx)
            .map(|(s, e)| (sc_span.0 + s, sc_span.0 + e))
            .unwrap_or(sc_span);
        units.push(EvalUnit::EmbeddedCommand {
            source: source.clone(),
            span,
        });
    }
}

/// Scan `input` for top-level command-substitution-like markers — `$(…)`,
/// backtick `…`, `<(…)`, `>(…)` — and return the inner content's byte range
/// (relative to `input`) for each. Skips over single-quoted regions and
/// backslash escapes, recurses through double-quoted regions to catch
/// embedded `$(…)` / backticks. Nested substitutions inside an outer
/// substitution are not reported here — they are picked up by the engine's
/// recursive evaluation step.
fn find_substitution_spans(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    let mut in_double_quote = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if !in_double_quote && c == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if c == b'"' {
            in_double_quote = !in_double_quote;
            i += 1;
            continue;
        }
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            // Skip arithmetic `$((…))` — not a command substitution.
            if i + 2 < bytes.len() && bytes[i + 2] == b'(' {
                let inner_start = i + 3;
                if let Some(end) = find_arith_close(bytes, inner_start) {
                    i = end + 2; // consume the trailing `))`
                    continue;
                }
                i += 3;
                continue;
            }
            let inner_start = i + 2;
            if let Some(end) = find_balanced_paren(bytes, inner_start) {
                spans.push((inner_start, end));
                i = end + 1;
                continue;
            }
            // Unclosed `$(...)` — the lexer's `read_balanced_parens` tolerates
            // EOF and produces a body spanning to end-of-input. Mirror that
            // here so the parser-extracted source pairs with this span by
            // index. Stop scanning because everything left is inside the
            // unclosed body.
            spans.push((inner_start, bytes.len()));
            break;
        }
        if c == b'`' {
            let inner_start = i + 1;
            let mut j = inner_start;
            while j < bytes.len() {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'`' {
                    break;
                }
                j += 1;
            }
            spans.push((inner_start, j));
            i = j + 1;
            continue;
        }
        if !in_double_quote
            && (c == b'<' || c == b'>')
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'('
        {
            let inner_start = i + 2;
            if let Some(end) = find_balanced_paren(bytes, inner_start) {
                spans.push((inner_start, end));
                i = end + 1;
                continue;
            }
            // Unclosed `<(...)` / `>(...)` — same EOF-tolerant fallback as
            // `$(...)` above; pair this span with the lexer-produced source
            // and stop so we don't re-scan into the unclosed body.
            spans.push((inner_start, bytes.len()));
            break;
        }
        i += 1;
    }
    spans
}

/// Find the position of the closing `)` matching an opening `(` — `start`
/// points at the byte immediately after the opener. Returns the byte offset
/// of the closing `)`. Skips quoted regions and backslash escapes.
pub(crate) fn find_balanced_paren(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i = start;
    let mut in_double_quote = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if !in_double_quote && c == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if c == b'"' {
            in_double_quote = !in_double_quote;
            i += 1;
            continue;
        }
        if !in_double_quote {
            if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Locate the `))` terminator for `$((expr))`. Returns the position of the
/// first `)` of the pair.
fn find_arith_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b')' {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_shell_parser::parse;

    fn decompose_input(input: &str) -> Vec<EvalUnit> {
        let cmd = parse(input).into_command();
        decompose(&cmd, input)
    }

    #[test]
    fn decompose_simple_command() {
        let units = decompose_input("echo hello world");
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0],
            EvalUnit::SimpleCommand {
                command: "echo".into(),
                args: vec!["hello".into(), "world".into()],
                span: (0, 16),
            }
        );
    }

    #[test]
    fn decompose_pipeline() {
        let units = decompose_input("echo foo | grep bar");
        assert_eq!(units.len(), 2);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
        assert!(matches!(&units[1], EvalUnit::SimpleCommand { command, .. } if command == "grep"));
    }

    #[test]
    fn decompose_and_or() {
        let units = decompose_input("a && b || c");
        let commands: Vec<_> = units
            .iter()
            .filter_map(|u| match u {
                EvalUnit::SimpleCommand { command, .. } => Some(command.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(commands, vec!["a", "b", "c"]);
    }

    #[test]
    fn decompose_sequence() {
        let units = decompose_input("a; b; c");
        assert_eq!(units.len(), 3);
    }

    #[test]
    fn decompose_subshell() {
        let units = decompose_input("(echo hello && rm -rf /)");
        assert_eq!(units.len(), 2);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
        assert!(matches!(&units[1], EvalUnit::SimpleCommand { command, .. } if command == "rm"));
    }

    #[test]
    fn decompose_if() {
        let units = decompose_input("if true; then echo yes; else rm /; fi");
        let commands: Vec<_> = units
            .iter()
            .filter_map(|u| match u {
                EvalUnit::SimpleCommand { command, .. } => Some(command.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(commands, vec!["true", "echo", "rm"]);
    }

    #[test]
    fn decompose_for_loop() {
        let units = decompose_input("for x in a b; do echo $x; done");
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_case() {
        let units = decompose_input("case $x in a) echo a;; b) rm b;; esac");
        let commands: Vec<_> = units
            .iter()
            .filter_map(|u| match u {
                EvalUnit::SimpleCommand { command, .. } => Some(command.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(commands, vec!["echo", "rm"]);
    }

    #[test]
    fn decompose_dynamic_command_name() {
        let units = decompose_input("$EDITOR file.txt");
        assert!(!units.is_empty());
        assert!(
            matches!(&units[0], EvalUnit::DynamicCommand { reason, .. } if reason.contains("$EDITOR"))
        );
    }

    #[test]
    fn decompose_glob_command_name() {
        let units = decompose_input("./bin/* --help");
        // Glob in command name → dynamic
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::DynamicCommand { .. })),
            "expected DynamicCommand for glob command name, got: {:?}",
            units
        );
    }

    #[test]
    fn decompose_command_substitution_in_arg() {
        let units = decompose_input("echo $(rm -rf /)");
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::SimpleCommand { command, .. } if command == "echo"))
        );
        assert!(units.iter().any(
            |u| matches!(u, EvalUnit::EmbeddedCommand { source, .. } if source == "rm -rf /")
        ));
    }

    #[test]
    fn decompose_backtick_in_arg() {
        let units = decompose_input("echo `date`");
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::EmbeddedCommand { source, .. } if source == "date"))
        );
    }

    #[test]
    fn decompose_process_substitution() {
        let units = decompose_input("diff <(ls /a) <(ls /b)");
        let embedded: Vec<_> = units
            .iter()
            .filter_map(|u| match u {
                EvalUnit::EmbeddedCommand { source, .. } => Some(source.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(embedded.len(), 2);
        assert!(embedded.contains(&"ls /a"));
        assert!(embedded.contains(&"ls /b"));
    }

    #[test]
    fn decompose_substitution_as_command_name() {
        let units = decompose_input("$(which python) --version");
        // Command name is dynamic → DynamicCommand
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::DynamicCommand { .. }))
        );
        // Also extracts the embedded command
        assert!(units.iter().any(
            |u| matches!(u, EvalUnit::EmbeddedCommand { source, .. } if source == "which python")
        ));
    }

    #[test]
    fn decompose_empty_input() {
        let units = decompose_input("");
        assert!(units.is_empty());
    }

    #[test]
    fn decompose_assignment_only() {
        let units = decompose_input("FOO=bar");
        assert!(units.is_empty());
    }

    #[test]
    fn decompose_background() {
        let units = decompose_input("sleep 10 &");
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "sleep"));
    }

    #[test]
    fn decompose_function_def() {
        let units = decompose_input("foo() { echo hello; }");
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_redirected() {
        let units = decompose_input("echo hello > /tmp/out");
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_quoted_command_name() {
        let units = decompose_input("\"echo\" hello");
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }
}

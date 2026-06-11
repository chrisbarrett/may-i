use may_i_shell_parser::{
    Command, ParseDiagnostic, SimpleCommand, SubstitutionForm, extract_simple_commands,
};

/// Byte range in the original input string covered by an `EvalUnit`.
pub(super) type Span = (usize, usize);

/// Surface form of a `$( … )` / backtick substitution that the engine
/// names in bubbled-up `:ask` reasons. `None` is used for substitution
/// shapes that should not be named in the reason (currently process
/// substitution, which the spec does not require an annotation for).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbeddedKind {
    Backtick,
    Dollar,
}

fn kind_from_form(form: SubstitutionForm) -> Option<EmbeddedKind> {
    match form {
        SubstitutionForm::Backtick => Some(EmbeddedKind::Backtick),
        SubstitutionForm::Dollar => Some(EmbeddedKind::Dollar),
        SubstitutionForm::Process => None,
    }
}

/// A unit of evaluation extracted from an AST.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum EvalUnit {
    /// A simple command extracted from the AST.
    SimpleCommand {
        command: String,
        args: Vec<String>,
        span: Span,
    },
    /// An embedded command found in a word part (substitution).
    EmbeddedCommand {
        source: String,
        span: Span,
        kind: Option<EmbeddedKind>,
    },
    /// A command with a dynamic name that cannot be resolved.
    DynamicCommand { reason: String, span: Span },
}

impl EvalUnit {
    /// Byte range in the original input covered by this unit.
    #[must_use]
    pub(crate) fn span(&self) -> Span {
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
pub(crate) fn decompose(
    cmd: &Command,
    input: &str,
    diagnostics: &[ParseDiagnostic],
) -> Vec<EvalUnit> {
    let simple_commands = extract_simple_commands(cmd);
    let mut units = Vec::new();

    for sc in simple_commands {
        decompose_simple_command(sc, input, diagnostics, &mut units);
    }

    units
}

fn decompose_simple_command(
    sc: &SimpleCommand,
    _input: &str,
    diagnostics: &[ParseDiagnostic],
    units: &mut Vec<EvalUnit>,
) {
    let sc_span = (sc.span.start, sc.span.end);

    // Check for assignment-only commands (no words)
    if sc.words.is_empty() {
        for assignment in &sc.assignments {
            push_embedded_units_from_word(&assignment.value, diagnostics, units);
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

    for word in &sc.words {
        push_embedded_units_from_word(word, diagnostics, units);
    }
}

/// Emit one `EvalUnit::EmbeddedCommand` per substitution in `word`, reading
/// each substitution's source-byte span directly from the AST. The parser's
/// `WordPart` already carries the inner-span the engine needs, so no flat
/// re-scan over the input is required.
///
/// A substitution the parser flags as unterminated is skipped: its "source"
/// is the swallowed tail of the input, not a command, so recursing into it
/// would fabricate a `No rule for command …` reason. The Error-severity
/// diagnostic floor owns that outcome instead. Whether a substitution is
/// terminated is the parser's judgement (`Embedded::terminated`) — the engine
/// no longer correlates spans against diagnostics.
fn push_embedded_units_from_word(
    word: &may_i_shell_parser::Word,
    diagnostics: &[ParseDiagnostic],
    units: &mut Vec<EvalUnit>,
) {
    for embedded in word.extract_embedded(diagnostics) {
        if !embedded.terminated {
            continue;
        }
        units.push(EvalUnit::EmbeddedCommand {
            source: embedded.source.to_string(),
            span: (embedded.span.start, embedded.span.end),
            kind: kind_from_form(embedded.form),
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use may_i_shell_parser::parse;

    fn decompose_input(input: &str) -> Vec<EvalUnit> {
        let result = parse(input);
        decompose(&result.command, input, &result.diagnostics)
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
        assert!(units.iter().any(|u| matches!(
            u,
            EvalUnit::EmbeddedCommand { source, kind: Some(EmbeddedKind::Dollar), .. }
                if source == "rm -rf /"
        )));
    }

    #[test]
    fn decompose_backtick_in_arg() {
        let units = decompose_input("echo `date`");
        assert!(units.iter().any(|u| matches!(
            u,
            EvalUnit::EmbeddedCommand { source, kind: Some(EmbeddedKind::Backtick), .. }
                if source == "date"
        )));
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
        // Also extracts the embedded command, carrying the $( … ) kind.
        assert!(units.iter().any(|u| matches!(
            u,
            EvalUnit::EmbeddedCommand { source, kind: Some(EmbeddedKind::Dollar), .. }
                if source == "which python"
        )));
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

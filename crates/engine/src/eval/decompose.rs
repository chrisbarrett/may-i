use may_i_shell_parser::{Command, SimpleCommand, extract_simple_commands};

/// A unit of evaluation extracted from an AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalUnit {
    /// A simple command extracted from the AST.
    SimpleCommand { command: String, args: Vec<String> },
    /// An embedded command found in a word part (substitution).
    EmbeddedCommand { source: String },
    /// A command with a dynamic name that cannot be resolved.
    DynamicCommand { reason: String },
}

/// Walk the AST and extract all evaluation units.
///
/// For each simple command in the AST:
/// - If the command name is dynamic, emit `DynamicCommand`
/// - Otherwise, emit `SimpleCommand`
/// - For all word parts across command name and arguments, extract embedded
///   commands (substitutions) as `EmbeddedCommand`
pub fn decompose(cmd: &Command) -> Vec<EvalUnit> {
    let simple_commands = extract_simple_commands(cmd);
    let mut units = Vec::new();

    for sc in simple_commands {
        decompose_simple_command(sc, &mut units);
    }

    units
}

fn decompose_simple_command(sc: &SimpleCommand, units: &mut Vec<EvalUnit>) {
    // Check for assignment-only commands (no words)
    if sc.words.is_empty() {
        // Extract embedded commands from assignment values
        for assignment in &sc.assignments {
            for embedded in assignment.value.extract_embedded_commands() {
                units.push(EvalUnit::EmbeddedCommand {
                    source: embedded.to_string(),
                });
            }
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
        });
    } else {
        let command = first_word.to_str();
        let args: Vec<String> = sc.words[1..].iter().map(|w| w.to_str()).collect();
        units.push(EvalUnit::SimpleCommand { command, args });
    }

    // Extract embedded commands from all words (including command name)
    for word in &sc.words {
        for embedded in word.extract_embedded_commands() {
            units.push(EvalUnit::EmbeddedCommand {
                source: embedded.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_shell_parser::parse;

    #[test]
    fn decompose_simple_command() {
        let cmd = parse("echo hello world");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0],
            EvalUnit::SimpleCommand {
                command: "echo".into(),
                args: vec!["hello".into(), "world".into()],
            }
        );
    }

    #[test]
    fn decompose_pipeline() {
        let cmd = parse("echo foo | grep bar");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 2);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
        assert!(matches!(&units[1], EvalUnit::SimpleCommand { command, .. } if command == "grep"));
    }

    #[test]
    fn decompose_and_or() {
        let cmd = parse("a && b || c");
        let units = decompose(&cmd);
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
        let cmd = parse("a; b; c");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 3);
    }

    #[test]
    fn decompose_subshell() {
        let cmd = parse("(echo hello && rm -rf /)");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 2);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
        assert!(matches!(&units[1], EvalUnit::SimpleCommand { command, .. } if command == "rm"));
    }

    #[test]
    fn decompose_if() {
        let cmd = parse("if true; then echo yes; else rm /; fi");
        let units = decompose(&cmd);
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
        let cmd = parse("for x in a b; do echo $x; done");
        let units = decompose(&cmd);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_case() {
        let cmd = parse("case $x in a) echo a;; b) rm b;; esac");
        let units = decompose(&cmd);
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
        let cmd = parse("$EDITOR file.txt");
        let units = decompose(&cmd);
        assert!(units.len() >= 1);
        assert!(
            matches!(&units[0], EvalUnit::DynamicCommand { reason } if reason.contains("$EDITOR"))
        );
    }

    #[test]
    fn decompose_glob_command_name() {
        let cmd = parse("./bin/* --help");
        let units = decompose(&cmd);
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
        let cmd = parse("echo $(rm -rf /)");
        let units = decompose(&cmd);
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::SimpleCommand { command, .. } if command == "echo"))
        );
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::EmbeddedCommand { source } if source == "rm -rf /"))
        );
    }

    #[test]
    fn decompose_backtick_in_arg() {
        let cmd = parse("echo `date`");
        let units = decompose(&cmd);
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::EmbeddedCommand { source } if source == "date"))
        );
    }

    #[test]
    fn decompose_process_substitution() {
        let cmd = parse("diff <(ls /a) <(ls /b)");
        let units = decompose(&cmd);
        let embedded: Vec<_> = units
            .iter()
            .filter_map(|u| match u {
                EvalUnit::EmbeddedCommand { source } => Some(source.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(embedded.len(), 2);
        assert!(embedded.contains(&"ls /a"));
        assert!(embedded.contains(&"ls /b"));
    }

    #[test]
    fn decompose_substitution_as_command_name() {
        let cmd = parse("$(which python) --version");
        let units = decompose(&cmd);
        // Command name is dynamic → DynamicCommand
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::DynamicCommand { .. }))
        );
        // Also extracts the embedded command
        assert!(units.iter().any(
            |u| matches!(u, EvalUnit::EmbeddedCommand { source } if source == "which python")
        ));
    }

    #[test]
    fn decompose_empty_input() {
        let cmd = parse("");
        let units = decompose(&cmd);
        assert!(units.is_empty());
    }

    #[test]
    fn decompose_assignment_only() {
        let cmd = parse("FOO=bar");
        let units = decompose(&cmd);
        assert!(units.is_empty());
    }

    #[test]
    fn decompose_background() {
        let cmd = parse("sleep 10 &");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "sleep"));
    }

    #[test]
    fn decompose_function_def() {
        let cmd = parse("foo() { echo hello; }");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_redirected() {
        let cmd = parse("echo hello > /tmp/out");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }

    #[test]
    fn decompose_quoted_command_name() {
        let cmd = parse("\"echo\" hello");
        let units = decompose(&cmd);
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }
}

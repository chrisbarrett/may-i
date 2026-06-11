use may_i_shell_parser::{
    Command, ParseDiagnostic, Redirection, RedirectionKind, RedirectionTarget, SimpleCommand,
    SubstitutionForm, extract_simple_commands,
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

/// Expansion provenance of one argv token. `None` when the token's source
/// word is literal (its text is its runtime value); `Some(display)` when
/// the word is expansion-bearing, where `display` is the source-faithful
/// rendering (`/tmp/$HOME`, not the flattened `/tmp/HOME`) used in floor
/// reasons. The security model forbids such a token from satisfying a
/// non-wildcard matcher toward `:allow`.
pub(crate) type Expansion = Option<String>;

/// A unit of evaluation extracted from an AST.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum EvalUnit {
    /// A simple command extracted from the AST.
    SimpleCommand {
        command: String,
        args: Vec<String>,
        /// Per-token expansion provenance, aligned with `args`.
        arg_expansions: Vec<Expansion>,
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
    /// A `NAME=VALUE` environment-assignment prefix. Floors the decision
    /// to at least `:ask` unless `NAME` is in the effective safe-env-vars
    /// set — a prefix such as `LD_PRELOAD=…` changes what executes, so
    /// evaluating the command as if unprefixed authorises a materially
    /// different command.
    EnvPrefix { name: String, span: Span },
    /// A redirection to a non-standard file target (`> path`, `< path`,
    /// …). Not silently ignored: floors the decision to at least `:ask`,
    /// naming the operator and target. `/dev/null` and fd duplication are
    /// standard plumbing and are never emitted.
    RedirectTarget {
        operator: &'static str,
        target: String,
        span: Span,
    },
}

impl EvalUnit {
    /// Byte range in the original input covered by this unit.
    #[must_use]
    pub(crate) fn span(&self) -> Span {
        match self {
            EvalUnit::SimpleCommand { span, .. }
            | EvalUnit::EmbeddedCommand { span, .. }
            | EvalUnit::DynamicCommand { span, .. }
            | EvalUnit::EnvPrefix { span, .. }
            | EvalUnit::RedirectTarget { span, .. } => *span,
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

    // Redirect targets carry their own embedded commands — a process
    // substitution in redirect position (`… < <(rm)`) attaches to the
    // enclosing `Redirected` wrapper, not to any simple command's words, so
    // it is invisible to the word scan above. Walk the whole tree for
    // redirect targets so those inner commands are evaluated too.
    push_embedded_units_from_redirect_targets(cmd, diagnostics, &mut units);

    units
}

/// Walk the command tree and emit embedded units for every redirect-target
/// word. Covers both a simple command's own redirections and the
/// `Redirected` wrapper that carries a compound's redirections (where a
/// `done < <(cmd)` process substitution lives).
fn push_embedded_units_from_redirect_targets(
    cmd: &Command,
    diagnostics: &[ParseDiagnostic],
    units: &mut Vec<EvalUnit>,
) {
    let (redirections, span): (&[Redirection], Span) = match cmd {
        Command::Simple(sc) => (sc.redirections.as_slice(), (sc.span.start, sc.span.end)),
        Command::Redirected {
            command,
            redirections,
        } => (redirections.as_slice(), first_simple_span(command)),
        _ => (&[], (0, 0)),
    };
    for redirection in redirections {
        match &redirection.target {
            RedirectionTarget::File(word) => {
                push_embedded_units_from_word(word, diagnostics, units);
                push_redirect_floor(redirection, word, span, units);
            }
            // An unquoted heredoc body is expanded by bash, so the parser
            // extracts its embedded command/arithmetic substitutions;
            // each becomes its own evaluation unit, exactly as for `$(…)`
            // in argument position. Quoted bodies carry no substitutions.
            RedirectionTarget::Heredoc { substitutions, .. } => {
                let word = may_i_shell_parser::Word {
                    parts: substitutions.clone(),
                };
                push_embedded_units_from_word(&word, diagnostics, units);
            }
            RedirectionTarget::Fd(_) => {}
        }
    }
    for child in cmd.children() {
        push_embedded_units_from_redirect_targets(child, diagnostics, units);
    }
}

/// Span of the first simple command under `cmd`, for floor units hanging
/// off a compound's `Redirected` wrapper.
fn first_simple_span(cmd: &Command) -> Span {
    fn walk(cmd: &Command) -> Option<Span> {
        if let Command::Simple(sc) = cmd {
            return Some((sc.span.start, sc.span.end));
        }
        cmd.children().iter().find_map(|c| walk(c))
    }
    walk(cmd).unwrap_or((0, 0))
}

/// Emit a `RedirectTarget` floor unit for a redirection to a file target,
/// unless it is standard plumbing. Plumbing is: a target of exactly
/// `/dev/null` (literal — an expansion-bearing target proves nothing),
/// fd-duplication forms (`2>&1` parses to an Fd target and never reaches
/// here; `>&-` closes an fd), and heredocs/herestrings (stdin data, not a
/// file the command names).
fn push_redirect_floor(
    redirection: &Redirection,
    word: &may_i_shell_parser::Word,
    span: Span,
    units: &mut Vec<EvalUnit>,
) {
    let operator = match redirection.kind {
        RedirectionKind::Input => "<",
        RedirectionKind::Output => ">",
        RedirectionKind::Append => ">>",
        RedirectionKind::Clobber => ">|",
        RedirectionKind::DupInput => "<&",
        RedirectionKind::DupOutput => ">&",
        // Heredocs are handled by substitution extraction; a herestring
        // feeds literal data to stdin (its embedded commands are covered
        // by the word scan above).
        RedirectionKind::Heredoc | RedirectionKind::HeredocStrip | RedirectionKind::Herestring => {
            return;
        }
    };
    let target = if word.is_expansion_bearing() {
        word.display_source()
    } else {
        let text = word.to_str();
        if text == "/dev/null" {
            return;
        }
        // `>&-` / `<&-` close an fd — plumbing, not a file target.
        if text == "-"
            && matches!(
                redirection.kind,
                RedirectionKind::DupInput | RedirectionKind::DupOutput
            )
        {
            return;
        }
        text
    };
    units.push(EvalUnit::RedirectTarget {
        operator,
        target,
        span,
    });
}

fn decompose_simple_command(
    sc: &SimpleCommand,
    _input: &str,
    diagnostics: &[ParseDiagnostic],
    units: &mut Vec<EvalUnit>,
) {
    let sc_span = (sc.span.start, sc.span.end);

    // Environment-assignment prefixes gate the decision: each one is its
    // own unit so a name outside the effective safe-env-vars set floors
    // the segment. Embedded commands in the assigned values are extracted
    // regardless. Assignment-only commands (`FOO=bar` with no words) gate
    // the same way — the assignment changes shell state.
    for assignment in &sc.assignments {
        units.push(EvalUnit::EnvPrefix {
            name: assignment.name.clone(),
            span: sc_span,
        });
        push_embedded_units_from_word(&assignment.value, diagnostics, units);
    }

    if sc.words.is_empty() {
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
        let arg_expansions: Vec<Expansion> = sc.words[1..]
            .iter()
            .map(|w| w.is_expansion_bearing().then(|| w.display_source()))
            .collect();
        units.push(EvalUnit::SimpleCommand {
            command,
            args,
            arg_expansions,
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
                arg_expansions: vec![None, None],
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
    fn decompose_process_substitution_redirect_target() {
        // `done < <(cmd)` — the procsub lives on the Redirected wrapper's
        // redirection target, not in any simple command's words.
        let units = decompose_input("while read x; do :; done < <(rm -rf /danger)");
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::EmbeddedCommand { source, kind: None, .. }
                    if source == "rm -rf /danger"
            )),
            "expected embedded `rm` from redirect target, got: {units:?}"
        );
    }

    #[test]
    fn decompose_simple_command_procsub_redirect_target() {
        // `cat < <(cmd)` — the redirection attaches to the simple command
        // itself, exercising the walker's `Command::Simple` branch.
        let units = decompose_input("cat < <(rm -rf /danger)");
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::EmbeddedCommand { source, kind: None, .. }
                    if source == "rm -rf /danger"
            )),
            "expected embedded `rm` from redirect target, got: {units:?}"
        );
    }

    #[test]
    fn decompose_command_substitution_redirect_target() {
        // A `$( … )` in a redirect target runs a command too (`cat < $(rm)`
        // executes the `rm`); the redirect-target walk evaluates it with its
        // `$(…)` kind so the reason can name the substitution form.
        let units = decompose_input("cat < $(rm -rf /)");
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::EmbeddedCommand { source, kind: Some(EmbeddedKind::Dollar), .. }
                    if source == "rm -rf /"
            )),
            "expected embedded `rm` from redirect target, got: {units:?}"
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
        assert_eq!(units.len(), 2);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
        assert!(
            matches!(
                &units[1],
                EvalUnit::RedirectTarget { operator: ">", target, .. } if target == "/tmp/out"
            ),
            "redirect target surfaces as a floor unit: {:?}",
            units[1]
        );
    }

    #[test]
    fn decompose_dev_null_redirect_is_plumbing() {
        let units = decompose_input("echo hello > /dev/null 2>&1");
        assert_eq!(units.len(), 1, "{units:?}");
    }

    #[test]
    fn decompose_assignment_prefix_unit() {
        let units = decompose_input("LD_PRELOAD=/evil.so git status");
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::EnvPrefix { name, .. } if name == "LD_PRELOAD")),
            "{units:?}"
        );
    }

    #[test]
    fn decompose_quoted_command_name() {
        let units = decompose_input("\"echo\" hello");
        assert_eq!(units.len(), 1);
        assert!(matches!(&units[0], EvalUnit::SimpleCommand { command, .. } if command == "echo"));
    }
}

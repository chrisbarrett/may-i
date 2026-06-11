use proptest::prelude::*;

use crate::ast::{Command, SimpleCommand};
use crate::diagnostic::Severity;

/// Reserved-word spellings plus a few ordinary identifiers. A generator
/// pool for argument words that exercises the command-position rule.
const RESERVED_AND_IDENTS: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "in", "while", "until", "do", "done", "case",
    "esac", "function", "{", "}", "foo", "bar", "baz",
];

/// First simple command's command name as the lexer reports it.
fn first_command_name(input: &str) -> Option<String> {
    fn walk(cmd: &Command) -> Option<&SimpleCommand> {
        match cmd {
            Command::Simple(sc) => Some(sc),
            Command::Pipeline(cs) | Command::Sequence(cs) => cs.iter().find_map(walk),
            Command::And(l, _) | Command::Or(l, _) => walk(l),
            Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => walk(c),
            Command::Redirected { command, .. } => walk(command),
            _ => None,
        }
    }
    walk(&crate::parse(input).command).and_then(|sc| sc.words.first().map(|w| w.to_str()))
}

/// Generate a "safe" unquoted command string: ASCII identifier words
/// separated by single spaces, optionally followed by an operator and
/// another identifier. Restricted to characters where inserting
/// `\<NL>` cannot land inside a quoted region.
fn arb_safe_command() -> impl Strategy<Value = String> {
    let ident = "[a-z][a-z0-9_]{0,5}";
    let args = proptest::collection::vec(ident, 0..3);
    (ident, args).prop_map(|(cmd, args)| {
        let mut out = cmd;
        for a in args {
            out.push(' ');
            out.push_str(&a);
        }
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn parse_never_panics(input in any::<String>()) {
        let _ = crate::parse(&input);
    }

    /// POSIX 2.2.1: an unquoted `\<newline>` is removed from the input
    /// before tokenisation. Inserting `\<newline>` sequences at positions
    /// in the original (un-escaped) command MUST NOT change the first
    /// command name the lexer sees. The insertion positions are picked
    /// against the *original* string, so each insertion lands in a clean
    /// unquoted context (no chance of pairing with an adjacent `\`).
    #[test]
    fn prop_line_continuation_is_transparent(
        base in arb_safe_command(),
        raw_positions in proptest::collection::vec(0usize..1000, 0..8),
    ) {
        let baseline = first_command_name(&base);

        let len = base.len();
        let mut positions: Vec<usize> = raw_positions
            .into_iter()
            .map(|p| if len == 0 { 0 } else { p % (len + 1) })
            .collect();
        positions.sort_unstable();

        let mut mutated = String::with_capacity(len + positions.len() * 2);
        let mut cursor = 0usize;
        for pos in positions {
            mutated.push_str(&base[cursor..pos]);
            mutated.push_str("\\\n");
            cursor = pos;
        }
        mutated.push_str(&base[cursor..]);

        let mutated_name = first_command_name(&mutated);
        prop_assert_eq!(
            mutated_name.as_deref(),
            baseline.as_deref(),
            "command name changed after `\\<NL>` insertion: base={:?} mutated={:?}",
            base,
            mutated
        );
    }

    /// No silent token loss: a simple command whose arguments include
    /// reserved-word spellings either preserves every word as a literal
    /// argument, or — if a keyword landed where the grammar could not place
    /// it — emits an Error-severity diagnostic. A word never just vanishes.
    #[test]
    fn prop_no_silent_token_loss(
        args in proptest::collection::vec(
            proptest::sample::select(RESERVED_AND_IDENTS),
            0..6,
        ),
    ) {
        // `cmd` is a fixed non-keyword: the input is always a simple command.
        let mut input = String::from("cmd");
        for a in &args {
            input.push(' ');
            input.push_str(a);
        }

        let result = crate::parse(&input);
        let has_error = result
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error);

        if has_error {
            // Divergence was surfaced (and floors the decision) — acceptable.
            return Ok(());
        }

        // No error ⇒ every input word must survive verbatim in argv.
        let words = match &result.command {
            Command::Simple(sc) => sc.words.iter().map(|w| w.to_str()).collect::<Vec<_>>(),
            other => panic!("expected Simple for input {input:?}, got {other:?}"),
        };
        let mut expected = vec![String::from("cmd")];
        expected.extend(args.iter().map(|a| a.to_string()));
        prop_assert_eq!(
            words,
            expected,
            "word silently dropped without an Error diagnostic: input={:?}",
            input
        );
    }
}

/// Every word reachable in any parse of any input answers
/// `is_expansion_bearing` without panicking (totality), and a word built
/// solely from single-quoted text is never expansion-bearing — quoting
/// suppresses every expansion the predicate detects.
fn walk_words(cmd: &Command, f: &mut impl FnMut(&crate::ast::Word)) {
    fn walk_sc(sc: &SimpleCommand, f: &mut impl FnMut(&crate::ast::Word)) {
        for w in &sc.words {
            f(w);
        }
        for a in &sc.assignments {
            f(&a.value);
        }
        for r in &sc.redirections {
            if let crate::ast::RedirectionTarget::File(w) = &r.target {
                f(w);
            }
        }
    }
    if let Command::Simple(sc) = cmd {
        walk_sc(sc, f);
    }
    for child in cmd.children() {
        walk_words(child, f);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn prop_is_expansion_bearing_total(input in any::<String>()) {
        let result = crate::parse(&input);
        walk_words(&result.command, &mut |w| {
            let _ = w.is_expansion_bearing();
        });
    }

    /// A single-quoted word is never expansion-bearing, whatever it
    /// contains — `rm '<anything>'` names one literal file.
    #[test]
    fn prop_single_quoted_word_never_expansion_bearing(
        body in "[a-zA-Z0-9 ${}*?\\[\\]~,()-]{0,20}",
    ) {
        let input = format!("rm '{body}'");
        let result = crate::parse(&input);
        prop_assert!(!result.has_errors(), "unexpected parse error for {input:?}");
        walk_words(&result.command, &mut |w| {
            assert!(
                !w.is_expansion_bearing(),
                "single-quoted arg flagged for input {input:?}: {w:?}"
            );
        });
    }

    /// Plain identifier-ish literals are never expansion-bearing.
    #[test]
    fn prop_plain_literal_never_expansion_bearing(
        body in "[a-zA-Z0-9_./:-]{1,20}",
    ) {
        let input = format!("rm {body}");
        let result = crate::parse(&input);
        walk_words(&result.command, &mut |w| {
            assert!(
                !w.is_expansion_bearing(),
                "literal arg flagged for input {input:?}: {w:?}"
            );
        });
    }
}

/// Heredoc-substitution properties: an embedded command reachable via an
/// unquoted heredoc body is always extracted; a quoted body never yields
/// substitutions, whatever it contains.
fn first_heredoc_substitutions(input: &str) -> Option<Vec<crate::ast::WordPart>> {
    fn walk(cmd: &Command) -> Option<Vec<crate::ast::WordPart>> {
        if let Command::Simple(sc) = cmd {
            for r in &sc.redirections {
                if let crate::ast::RedirectionTarget::Heredoc { substitutions, .. } = &r.target {
                    return Some(substitutions.clone());
                }
            }
        }
        cmd.children().iter().find_map(|c| walk(c))
    }
    walk(&crate::parse(input).command)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn prop_unquoted_heredoc_substitution_never_escapes(
        cmd in "[a-z][a-z0-9 ./-]{0,12}",
        before in "[a-zA-Z0-9 .]{0,8}",
        after in "[a-zA-Z0-9 .]{0,8}",
    ) {
        let input = format!("cat <<XEOF\n{before}$({cmd}){after}\nXEOF\n");
        let subs = first_heredoc_substitutions(&input)
            .expect("heredoc target present");
        prop_assert!(
            subs.iter().any(|p| matches!(
                p,
                crate::ast::WordPart::CommandSubstitution { source, .. } if source == &cmd
            )),
            "embedded command {cmd:?} escaped extraction for {input:?}: {subs:?}"
        );
    }

    #[test]
    fn prop_quoted_heredoc_body_yields_no_substitutions(
        body in "[a-zA-Z0-9 $()`{}*?~\\\\-]{0,24}",
    ) {
        let input = format!("cat <<'XEOF'\n{body}\nXEOF\n");
        let subs = first_heredoc_substitutions(&input)
            .expect("heredoc target present");
        prop_assert!(
            subs.is_empty(),
            "quoted body yielded substitutions for {input:?}: {subs:?}"
        );
    }
}

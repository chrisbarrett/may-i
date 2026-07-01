//! Oracle proptest: `zsh -n` is the ground truth for what the zsh grammar
//! accepts. For any input this suite generates that `zsh -n` accepts, parsing
//! under `Dialect::Zsh` MUST NOT emit an `Error`-severity diagnostic (which
//! would floor a correct command to `:ask`). The generator is deliberately
//! scoped to the constructs this change supports (shared bash forms plus the
//! two zsh-only forms); it does not probe the deferred long tail.
//!
//! Skipped entirely when `zsh` is absent from `PATH`.

use std::process::Command;
use std::sync::OnceLock;

use may_i_shell_parser::{Dialect, Severity, parse_with_dialect};
use proptest::prelude::*;

/// Whether a usable `zsh` is on `PATH`. Probed once.
fn zsh_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("zsh")
            .arg("-nc")
            .arg(":")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Whether `zsh -n` accepts `input` as syntactically valid (no execution).
fn zsh_accepts(input: &str) -> bool {
    Command::new("zsh")
        .arg("-nc")
        .arg(input)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A single simple command drawn from a fixed, safe vocabulary.
fn arb_simple() -> impl Strategy<Value = String> {
    let cmd = prop::sample::select(vec!["echo", "ls", "print", "true", "cat"]);
    let args = prop::collection::vec(
        prop::sample::select(vec!["hi", "-l", "foo", "a.txt", "x"]),
        0..3,
    );
    (cmd, args).prop_map(|(c, a)| {
        let mut s = c.to_string();
        for arg in a {
            s.push(' ');
            s.push_str(arg);
        }
        s
    })
}

/// A glob-qualified command: a glob word carrying a trailing `(…)` qualifier.
fn arb_glob_qualified() -> impl Strategy<Value = String> {
    let cmd = prop::sample::select(vec!["ls", "print -l", "stat"]);
    let glob = prop::sample::select(vec!["*", "**/*", "*.txt"]);
    let qualifier = prop::sample::select(vec!["(.)", "(/)", "(.om[1])", "(.N)", "(*)"]);
    (cmd, glob, qualifier).prop_map(|(c, g, q)| format!("{c} {g}{q}"))
}

/// One statement: a simple command, a glob-qualified command, a brace group,
/// or a function definition — each in both `;`-terminated and no-semicolon
/// forms where zsh allows the latter.
fn arb_statement() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_simple(),
        arb_glob_qualified(),
        // Bare brace group, with and without the trailing terminator.
        (arb_simple(), any::<bool>()).prop_map(|(c, semi)| {
            if semi {
                format!("{{ {c}; }}")
            } else {
                format!("{{ {c} }}")
            }
        }),
        // Function definition, with and without the trailing terminator.
        (
            prop::sample::select(vec!["foo", "cleanup", "greet"]),
            arb_simple(),
            any::<bool>(),
        )
            .prop_map(|(name, body, semi)| {
                if semi {
                    format!("{name}() {{ {body}; }}")
                } else {
                    format!("{name}() {{ {body} }}")
                }
            }),
    ]
}

/// A command line: 1–3 statements joined by a shell separator.
fn arb_command_line() -> impl Strategy<Value = String> {
    let sep = prop::sample::select(vec!["; ", " && ", " || ", " | "]);
    (
        arb_statement(),
        prop::collection::vec((sep, arb_statement()), 0..2),
    )
        .prop_map(|(head, rest)| {
            let mut s = head;
            for (sep, stmt) in rest {
                s.push_str(sep);
                s.push_str(&stmt);
            }
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn zsh_accepted_input_has_no_error_under_zsh_dialect(input in arb_command_line()) {
        if !zsh_available() {
            return Ok(());
        }
        // The oracle only constrains inputs zsh actually accepts.
        prop_assume!(zsh_accepts(&input));

        let result = parse_with_dialect(&input, Dialect::Zsh);
        let errors: Vec<_> = result
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        prop_assert!(
            errors.is_empty(),
            "zsh accepts {input:?} but the zsh dialect emitted Error diagnostics: {errors:?}"
        );
    }
}

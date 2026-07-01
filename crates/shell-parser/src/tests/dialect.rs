use crate::*;

// ── 1. Dialect type and parser plumbing ─────────────────────────────

#[test]
fn shared_construct_parses_identically_across_dialects() {
    let input = "if true; then echo hi; fi";
    let bash = parse(input);
    let zsh = parse_with_dialect(input, Dialect::Zsh);
    // The AST is identical for a construct well-formed in both dialects.
    assert_eq!(bash.command, zsh.command);
    // And both are diagnostic-free.
    assert!(bash.diagnostics.is_empty(), "bash: {:?}", bash.diagnostics);
    assert!(zsh.diagnostics.is_empty(), "zsh: {:?}", zsh.diagnostics);
}

#[test]
fn parse_delegates_to_bash_dialect() {
    let input = "for x in a b; do echo $x; done";
    assert_eq!(parse(input), parse_with_dialect(input, Dialect::Bash));
}

#[test]
fn dialect_default_is_bash() {
    assert_eq!(Dialect::default(), Dialect::Bash);
}

// ── 2. No-semicolon brace terminator (Zsh) ──────────────────────────

fn has_missing_brace_warning(diags: &[ParseDiagnostic]) -> bool {
    diags.iter().any(|d| {
        d.kind == ParseDiagnosticKind::MissingClosingKeyword { expected: "}" }
            && d.severity == Severity::Warning
    })
}

fn simple_command_names(cmd: &Command) -> Vec<String> {
    extract_simple_commands(cmd)
        .iter()
        .filter_map(|sc| sc.command_name().map(str::to_string))
        .collect()
}

#[test]
fn zsh_bare_brace_group_no_semicolon() {
    let r = parse_with_dialect("{ echo a }", Dialect::Zsh);
    assert!(r.diagnostics.is_empty(), "diags: {:?}", r.diagnostics);
    match &r.command {
        Command::BraceGroup(inner) => {
            assert_eq!(simple_command_names(inner), ["echo"]);
        }
        other => panic!("expected BraceGroup, got {other:?}"),
    }
}

#[test]
fn zsh_function_body_no_semicolon() {
    let r = parse_with_dialect("foo() { echo hi }", Dialect::Zsh);
    assert!(r.diagnostics.is_empty(), "diags: {:?}", r.diagnostics);
    match &r.command {
        Command::FunctionDef { name, body } => {
            assert_eq!(name, "foo");
            assert_eq!(simple_command_names(body), ["echo"]);
        }
        other => panic!("expected FunctionDef, got {other:?}"),
    }
}

#[test]
fn bash_brace_group_no_semicolon_still_warns() {
    // Under Bash the missing terminator is diagnosed exactly as today.
    let r = parse_with_dialect("{ echo a }", Dialect::Bash);
    assert!(
        has_missing_brace_warning(&r.diagnostics),
        "expected MissingClosingKeyword(}}), got: {:?}",
        r.diagnostics
    );
}

#[test]
fn bash_function_body_no_semicolon_still_warns() {
    let r = parse_with_dialect("foo() { echo hi }", Dialect::Bash);
    assert!(
        has_missing_brace_warning(&r.diagnostics),
        "expected MissingClosingKeyword(}}), got: {:?}",
        r.diagnostics
    );
}

#[test]
fn top_level_closing_brace_stays_literal_both_dialects() {
    // A `}` at top level (not inside a brace/function context) is a literal
    // argument in both dialects — the zsh terminator is scoped to groups.
    for dialect in [Dialect::Bash, Dialect::Zsh] {
        let r = parse_with_dialect("echo }", dialect);
        assert!(r.diagnostics.is_empty(), "{dialect:?}: {:?}", r.diagnostics);
        let sc = extract_simple_commands(&r.command);
        let words: Vec<String> = sc[0].words.iter().map(|w| w.to_str()).collect();
        assert_eq!(words, ["echo", "}"], "dialect {dialect:?}");
    }
}

#[test]
fn zsh_no_semicolon_ast_matches_semicolon_terminated_form() {
    // The spec requires the no-semicolon zsh form to produce the *same*
    // brace-group / function-definition structure as the `;`-terminated input.
    assert_eq!(
        parse_with_dialect("{ echo a }", Dialect::Zsh).command,
        parse("{ echo a; }").command,
    );
    assert_eq!(
        parse_with_dialect("foo() { echo hi }", Dialect::Zsh).command,
        parse("foo() { echo hi; }").command,
    );
}

#[test]
fn zsh_no_semicolon_body_surfaces_embedded_command() {
    // Strictness preserved: the body's `rm` is still in the AST for the
    // engine to evaluate.
    let r = parse_with_dialect(r#"cleanup() { rm -rf "$wt" }; cleanup"#, Dialect::Zsh);
    assert!(r.diagnostics.is_empty(), "diags: {:?}", r.diagnostics);
    assert!(
        simple_command_names(&r.command).contains(&"rm".to_string()),
        "expected rm in AST, got: {:?}",
        simple_command_names(&r.command)
    );
}

#[test]
fn zsh_glued_closing_brace_is_failsafe_warning() {
    // Documented limitation: a *glued* `}` (`hi}`) is not split in this pass,
    // so the group's terminator is lost and we fall back to today's Warning —
    // fail-safe (no Error, no silent drop). Only whitespace-delimited `}` is
    // recognised.
    let r = parse_with_dialect("{ echo hi}", Dialect::Zsh);
    assert!(
        has_missing_brace_warning(&r.diagnostics),
        "expected fail-safe MissingClosingKeyword(}}), got: {:?}",
        r.diagnostics
    );
    assert!(
        !r.has_errors(),
        "glued brace must stay a Warning, not an Error: {:?}",
        r.diagnostics
    );
}

// ── 3. Glob qualifiers (Zsh) ────────────────────────────────────────

/// The words of the first (only) simple command.
fn only_words(cmd: &Command) -> Vec<Word> {
    let scs = extract_simple_commands(cmd);
    assert_eq!(scs.len(), 1, "expected one simple command in {cmd:?}");
    scs[0].words.clone()
}

#[test]
fn zsh_glob_qualifier_recursive_star() {
    let r = parse_with_dialect("ls **/*(.)", Dialect::Zsh);
    assert!(r.diagnostics.is_empty(), "diags: {:?}", r.diagnostics);
    let words = only_words(&r.command);
    assert_eq!(words[0].to_str(), "ls");
    // The qualifier is folded into the glob argument word.
    assert_eq!(words[1].to_str(), "**/*(.)");
}

#[test]
fn zsh_glob_qualifier_with_ordering_flags() {
    let r = parse_with_dialect("print -l *(.om[1])", Dialect::Zsh);
    assert!(r.diagnostics.is_empty(), "diags: {:?}", r.diagnostics);
    let words = only_words(&r.command);
    assert_eq!(words.last().unwrap().to_str(), "*(.om[1])");
}

#[test]
fn bash_glob_qualifier_still_errors() {
    for input in ["ls **/*(.)", "print -l *(.om[1])"] {
        let r = parse_with_dialect(input, Dialect::Bash);
        assert!(
            r.has_errors(),
            "expected Error under Bash for {input:?}, got: {:?}",
            r.diagnostics
        );
    }
}

#[test]
fn zsh_qualified_glob_is_expansion_bearing() {
    // Strictness preserved: the folded qualifier word is expansion-bearing,
    // so an `:allow` resting on matching it floors exactly as a plain glob.
    let r = parse_with_dialect("print -l *(.om[1])", Dialect::Zsh);
    let words = only_words(&r.command);
    assert!(
        words.last().unwrap().is_expansion_bearing(),
        "qualified glob must stay expansion-bearing: {:?}",
        words.last().unwrap()
    );
}

#[test]
fn zsh_function_def_not_mistaken_for_qualifier() {
    // `name()` has no glob metachar, so the adjacent `(` is a function-def
    // paren, not a qualifier. Parses identically to bash.
    let input = "name() { echo hi; }";
    let zsh = parse_with_dialect(input, Dialect::Zsh);
    assert!(matches!(zsh.command, Command::FunctionDef { .. }));
    assert_eq!(zsh.command, parse(input).command);
}

#[test]
fn zsh_subshell_not_mistaken_for_qualifier() {
    // A space-separated `(` opens a subshell — not adjacent to a glob word,
    // so not a qualifier. Parses identically to bash.
    let input = "(cd /tmp; ls)";
    let zsh = parse_with_dialect(input, Dialect::Zsh);
    assert!(matches!(zsh.command, Command::Subshell(_)));
    assert_eq!(zsh.command, parse(input).command);
}

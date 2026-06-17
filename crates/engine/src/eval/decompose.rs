use may_i_shell_parser::{
    Command, ParseDiagnostic, Redirection, RedirectionKind, RedirectionTarget, SimpleCommand,
    SubstitutionForm, Word, WordPart, constant_env, defined_function_names,
    extract_simple_commands,
};
use std::collections::{HashMap, HashSet};

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
    /// A call to a function the same command defines. Resolves to `:allow`
    /// (the body is authorised once, at its definition) and never emits a
    /// `No rule for command …` reason. Embedded substitutions in the call's
    /// arguments are still extracted as their own `EmbeddedCommand` units.
    LocalFunctionCall { name: String, span: Span },
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
            | EvalUnit::LocalFunctionCall { span, .. }
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

    // Variables the command provably assigns a constant value. Used to resolve
    // a variable command name (`$BIN`) to its literal before declaring it
    // dynamic. Empty for commands with no qualifying assignment.
    let const_env = constant_env(cmd);

    // Spans of simple commands that are calls to a *live* script-local
    // function — the order/liveness-aware classification (D2). Anything not in
    // this set is decomposed as an ordinary command.
    let internal_call_spans = live_local_call_spans(cmd, &const_env);

    for sc in simple_commands {
        decompose_simple_command(
            sc,
            input,
            diagnostics,
            &const_env,
            &internal_call_spans,
            &mut units,
        );
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
    const_env: &HashMap<String, String>,
    internal_call_spans: &HashSet<Span>,
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

    // A dynamic first word that is a lone variable expansion (`$BIN`,
    // `${BIN}`, `"$BIN"`) is resolved against the command's provably-constant
    // env. On success it is evaluated as that literal command name; otherwise
    // it falls through to `DynamicCommand` exactly as before. Argument words
    // are never resolved here.
    let resolved_command = first_word
        .is_dynamic()
        .then(|| resolve_command_name(first_word, const_env))
        .flatten();

    if first_word.is_dynamic() && resolved_command.is_none() {
        units.push(EvalUnit::DynamicCommand {
            reason: format!(
                "dynamic command name: {}",
                first_word.dynamic_parts().join(", ")
            ),
            span: sc_span,
        });
    } else {
        let command = resolved_command.unwrap_or_else(|| first_word.to_str());
        if internal_call_spans.contains(&sc_span) {
            // A call to a function that is live at this point: internal, never
            // an external program. The body was authorised once at its
            // definition; argument substitutions are still extracted below.
            units.push(EvalUnit::LocalFunctionCall {
                name: command,
                span: sc_span,
            });
        } else {
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
    }

    for word in &sc.words {
        push_embedded_units_from_word(word, diagnostics, units);
    }
}

/// Resolve a first word that is a lone variable expansion to its literal
/// value in `const_env`. Returns `Some(command)` only when the word is exactly
/// one `$VAR`/`${VAR}` (optionally wrapped in a single pair of double quotes)
/// and that variable resolves to a non-empty literal. Anything else — a mixed
/// word, an operator expansion, or an unresolved variable — returns `None` so
/// the caller keeps the command dynamic.
fn resolve_command_name(first_word: &Word, const_env: &HashMap<String, String>) -> Option<String> {
    lone_variable_part(first_word)?;
    let resolved = first_word.resolve(const_env);
    if !resolved.is_literal() {
        return None;
    }
    let command = resolved.to_str();
    (!command.is_empty()).then_some(command)
}

/// The single inner part of a word that consists of exactly one plain variable
/// expansion, unwrapping a lone double-quote layer (`"$BIN"`). Returns `None`
/// for multi-part words and for operator expansions (`${BIN:-x}`).
fn lone_variable_part(word: &Word) -> Option<()> {
    let part = match word.parts.as_slice() {
        [WordPart::DoubleQuoted(inner)] => match inner.as_slice() {
            [p] => p,
            _ => return None,
        },
        [p] => p,
        _ => return None,
    };
    matches!(
        part,
        WordPart::Parameter(_) | WordPart::ParameterExpansion(_)
    )
    .then_some(())
}

// ── Liveness-aware local-function-call classification (D2) ──────────────────

/// The command name a simple command resolves to for classification — the same
/// value `decompose_simple_command` would emit as `command`. `None` when the
/// first word is a dynamic name that does not resolve (a `DynamicCommand`) or
/// the command has no words (assignment-only).
fn resolved_command_name(
    sc: &SimpleCommand,
    const_env: &HashMap<String, String>,
) -> Option<String> {
    let first_word = sc.words.first()?;
    if first_word.is_dynamic() {
        resolve_command_name(first_word, const_env)
    } else {
        Some(first_word.to_str())
    }
}

/// What an `unset -f …` statement removes from the live-function set.
enum UnsetEffect {
    /// Remove these statically-known names.
    Names(Vec<String>),
    /// A dynamic target (`unset -f "$x"`): could remove anything, so the whole
    /// live set must be cleared.
    All,
}

/// Recognise an `unset -f NAME…` simple command and report what it unsets.
/// Returns `None` for anything that is not a function-unset (a plain `unset`
/// touches variables, not functions, and is ignored here).
fn unset_f_effect(sc: &SimpleCommand, const_env: &HashMap<String, String>) -> Option<UnsetEffect> {
    if resolved_command_name(sc, const_env).as_deref() != Some("unset") {
        return None;
    }
    let args = &sc.words[1..];
    if !args.iter().any(|w| w.to_str() == "-f") {
        return None; // `unset` without `-f` unsets variables, not functions
    }
    let mut names = Vec::new();
    for w in args {
        let text = w.to_str();
        if text.starts_with('-') {
            continue; // a flag (`-f`, `-fv`, …)
        }
        if w.is_dynamic() || w.is_expansion_bearing() {
            return Some(UnsetEffect::All);
        }
        names.push(text);
    }
    Some(UnsetEffect::Names(names))
}

fn apply_unset(effect: &UnsetEffect, live: &mut HashSet<String>) {
    match effect {
        UnsetEffect::Names(names) => {
            for n in names {
                live.remove(n);
            }
        }
        UnsetEffect::All => live.clear(),
    }
}

/// Spans of simple commands that are calls to a *live* script-local function —
/// the ones `decompose` emits as `LocalFunctionCall`. Implements the two-tier
/// liveness analysis (design D2): top-level calls are order-sensitive (Tier 1);
/// calls inside function bodies and conditionally-reached regions use the
/// establishment set fixed at the activation point (Tier 2). Conservative
/// throughout — a call is internal only when the function is provably live
/// there, because a false internal would let an ungated external run.
fn live_local_call_spans(cmd: &Command, const_env: &HashMap<String, String>) -> HashSet<Span> {
    let defs = defined_function_names(cmd);
    let mut out = HashSet::new();
    if defs.is_empty() {
        return out;
    }

    // Tier 2 establishment set: the functions unconditionally defined at top
    // level before the activation point (the earliest non-body call to any
    // defined function), minus any name ever unset. Every body runs at or after
    // the activation point, so these are guaranteed live inside any body.
    let activation = activation_pos(cmd, const_env, &defs);
    let (unset_names, unset_all) = collect_unsets(cmd, const_env);
    let established: HashSet<String> = if unset_all {
        HashSet::new()
    } else {
        spine_def_positions(cmd)
            .into_iter()
            .filter(|(pos, name)| *pos < activation && !unset_names.contains(name))
            .map(|(_, name)| name)
            .collect()
    };

    let mut live: HashSet<String> = HashSet::new();
    classify(
        cmd,
        Mode::Spine,
        &mut live,
        &established,
        const_env,
        &mut out,
    );
    out
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// The top-level execution spine: statements run unconditionally, in order,
    /// in the current shell. Definitions persist; `unset -f` removes.
    Spine,
    /// A region that runs later or conditionally (a function body, a `&&`/`||`
    /// right operand, a background/pipeline subshell, or a compound interior).
    /// Calls are classified against the fixed establishment set.
    Deferred,
}

#[allow(clippy::only_used_in_recursion)]
fn classify(
    cmd: &Command,
    mode: Mode,
    live: &mut HashSet<String>,
    established: &HashSet<String>,
    const_env: &HashMap<String, String>,
    out: &mut HashSet<Span>,
) {
    match mode {
        Mode::Spine => match cmd {
            Command::Sequence(cmds) => {
                for c in cmds {
                    classify(c, Mode::Spine, live, established, const_env, out);
                }
            }
            // The right operand of `&&`/`||` runs conditionally — deferred. It
            // may also unset a name; drop anything it might unset from `live`.
            Command::And(a, b) | Command::Or(a, b) => {
                classify(a, Mode::Spine, live, established, const_env, out);
                classify(b, Mode::Deferred, live, established, const_env, out);
                remove_possible_unsets(b, const_env, live);
            }
            Command::Redirected { command, .. } => {
                classify(command, Mode::Spine, live, established, const_env, out);
            }
            Command::FunctionDef { name, body } => {
                if !name.is_empty() {
                    live.insert(name.clone());
                }
                classify(body, Mode::Deferred, live, established, const_env, out);
            }
            Command::Simple(sc) => {
                if let Some(effect) = unset_f_effect(sc, const_env) {
                    apply_unset(&effect, live);
                } else if let Some(name) = resolved_command_name(sc, const_env)
                    && live.contains(&name)
                {
                    out.insert((sc.span.start, sc.span.end));
                }
            }
            Command::Assignment(_) => {}
            // Background / pipeline stages run in subshells (defs do not persist
            // to the parent); compound interiors are conditionally reached.
            // Classify their calls as deferred and conservatively drop any name
            // the region might unset from the spine's `live` set.
            _ => {
                remove_possible_unsets(cmd, const_env, live);
                for child in cmd.children() {
                    classify(child, Mode::Deferred, live, established, const_env, out);
                }
            }
        },
        Mode::Deferred => {
            if let Command::Simple(sc) = cmd
                && let Some(name) = resolved_command_name(sc, const_env)
                && established.contains(&name)
            {
                out.insert((sc.span.start, sc.span.end));
            }
            for child in cmd.children() {
                classify(child, Mode::Deferred, live, established, const_env, out);
            }
        }
    }
}

/// Byte offset of the earliest non-body call to a defined-function name — the
/// point by which every function body must be live to be internal. `usize::MAX`
/// when nothing outside a body could invoke a function (no body runs, so
/// establishment is moot).
///
/// An "activation" is any non-body construct that could begin running a
/// function body: a direct call to a defined-function name, an `eval`/`source`/
/// `.`/`trap` (which can invoke a function from an opaque string), or a
/// command/backtick/process substitution (whose subshell could call any
/// function). Substitutions are treated opaquely — a substitution that runs no
/// function still caps establishment, which only costs a conservative `:ask`,
/// never a bypass. Missing one of these would let a function defined *after* the
/// hidden invocation be wrongly established.
fn activation_pos(
    cmd: &Command,
    const_env: &HashMap<String, String>,
    defs: &HashSet<String>,
) -> usize {
    fn walk(
        cmd: &Command,
        in_body: bool,
        const_env: &HashMap<String, String>,
        defs: &HashSet<String>,
        best: &mut usize,
    ) {
        if !in_body {
            if let Command::Simple(sc) = cmd
                && unset_f_effect(sc, const_env).is_none()
                && let Some(name) = resolved_command_name(sc, const_env)
                && (defs.contains(&name) || INVOKING_BUILTINS.contains(&name.as_str()))
            {
                *best = (*best).min(sc.span.start);
            }
            // Any command/backtick/process substitution runs a subshell that
            // could call a function — its position is an activation point.
            for word in command_words(cmd) {
                let mut starts = Vec::new();
                collect_substitution_starts(word, &mut starts);
                for s in starts {
                    *best = (*best).min(s);
                }
            }
        }
        let child_in_body = in_body || matches!(cmd, Command::FunctionDef { .. });
        for child in cmd.children() {
            walk(child, child_in_body, const_env, defs, best);
        }
    }
    let mut best = usize::MAX;
    walk(cmd, false, const_env, defs, &mut best);
    best
}

/// Builtins that can invoke a function from a string or installed handler,
/// beginning body execution at their own position regardless of source order.
const INVOKING_BUILTINS: &[&str] = &["eval", "source", ".", "trap"];

/// The words a command exposes directly (command words, assignment values,
/// redirect-target files). Used to locate substitutions that could invoke a
/// function. Does not descend into child commands — the caller recurses.
fn command_words(cmd: &Command) -> Vec<&Word> {
    let mut out: Vec<&Word> = Vec::new();
    match cmd {
        Command::Simple(sc) => {
            out.extend(&sc.words);
            out.extend(sc.assignments.iter().map(|a| &a.value));
            for r in &sc.redirections {
                if let RedirectionTarget::File(w) = &r.target {
                    out.push(w);
                }
            }
        }
        Command::Assignment(a) => out.push(&a.value),
        Command::For { words, .. } => out.extend(words),
        Command::Case { word, arms, .. } => {
            out.push(word);
            for arm in arms {
                out.extend(&arm.patterns);
            }
        }
        _ => {}
    }
    out
}

/// Byte offsets where a command/backtick/process substitution begins inside a
/// word (recursing through double-quoted parts). Arithmetic `$((…))` runs no
/// command and is excluded.
fn collect_substitution_starts(word: &Word, out: &mut Vec<usize>) {
    fn walk(parts: &[WordPart], out: &mut Vec<usize>) {
        for part in parts {
            match part {
                WordPart::CommandSubstitution { span, .. }
                | WordPart::Backtick { span, .. }
                | WordPart::ProcessSubstitution { span, .. } => out.push(span.start),
                WordPart::DoubleQuoted(inner) => walk(inner, out),
                _ => {}
            }
        }
    }
    walk(&word.parts, out);
}

/// Positions and names of functions defined unconditionally on the top-level
/// spine (not inside a conditional, subshell, pipeline, background, or another
/// function body). A definition's position is its body's first simple command —
/// after any preceding top-level statement, before any following one. These are
/// the only definitions eligible to *establish* a function for Tier 2.
fn spine_def_positions(cmd: &Command) -> Vec<(usize, String)> {
    fn walk(cmd: &Command, out: &mut Vec<(usize, String)>) {
        match cmd {
            Command::Sequence(cmds) => {
                for c in cmds {
                    walk(c, out);
                }
            }
            // Only the left operand of `&&`/`||` runs unconditionally.
            Command::And(a, _) | Command::Or(a, _) => walk(a, out),
            Command::Redirected { command, .. } => walk(command, out),
            // The body is not part of the top-level spine, so it is not walked.
            Command::FunctionDef { name, body } if !name.is_empty() => {
                out.push((first_simple_span(body).0, name.clone()));
            }
            // An empty-named def, and background / pipeline / compounds, do not
            // establish a persistent, unconditional definition.
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(cmd, &mut out);
    out
}

/// Union of every name any `unset -f` in the command removes, with a flag set
/// when any such statement has a dynamic target (could remove anything). Scans
/// the whole tree — conservative: a name unset anywhere is treated as never
/// reliably live for Tier 2.
fn collect_unsets(cmd: &Command, const_env: &HashMap<String, String>) -> (HashSet<String>, bool) {
    fn walk(
        cmd: &Command,
        const_env: &HashMap<String, String>,
        names: &mut HashSet<String>,
        all: &mut bool,
    ) {
        if let Command::Simple(sc) = cmd {
            match unset_f_effect(sc, const_env) {
                Some(UnsetEffect::Names(ns)) => names.extend(ns),
                Some(UnsetEffect::All) => *all = true,
                None => {}
            }
        }
        for child in cmd.children() {
            walk(child, const_env, names, all);
        }
    }
    let mut names = HashSet::new();
    let mut all = false;
    walk(cmd, const_env, &mut names, &mut all);
    (names, all)
}

/// Remove from `live` every name a region's subtree might `unset -f`. Used when
/// the spine walk steps over a conditionally-reached region: if the region runs
/// it may have unset the name, so it is no longer *definitely* live.
fn remove_possible_unsets(
    cmd: &Command,
    const_env: &HashMap<String, String>,
    live: &mut HashSet<String>,
) {
    if let Command::Simple(sc) = cmd
        && let Some(effect) = unset_f_effect(sc, const_env)
    {
        apply_unset(&effect, live);
    }
    for child in cmd.children() {
        remove_possible_unsets(child, const_env, live);
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
    fn decompose_local_function_call() {
        let units = decompose_input("materialise() { echo hi; }; materialise foo");
        // The body's `echo` is still a SimpleCommand.
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::SimpleCommand { command, .. } if command == "echo")),
            "expected body echo SimpleCommand, got: {units:?}"
        );
        // The call site resolves to a LocalFunctionCall, not a SimpleCommand.
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::LocalFunctionCall { name, .. } if name == "materialise"
            )),
            "expected LocalFunctionCall for materialise, got: {units:?}"
        );
        assert!(
            !units.iter().any(|u| matches!(
                u,
                EvalUnit::SimpleCommand { command, .. } if command == "materialise"
            )),
            "call to materialise must not be a SimpleCommand: {units:?}"
        );
    }

    #[test]
    fn decompose_local_function_call_extracts_arg_substitution() {
        let units = decompose_input("f() { :; }; f \"$(rm -rf /)\"");
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::LocalFunctionCall { name, .. } if name == "f")),
            "expected LocalFunctionCall for f, got: {units:?}"
        );
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::EmbeddedCommand { source, .. } if source == "rm -rf /"
            )),
            "embedded rm in a local call's args must still be extracted: {units:?}"
        );
    }

    fn internal_call_names(input: &str) -> Vec<String> {
        decompose_input(input)
            .iter()
            .filter_map(|u| match u {
                EvalUnit::LocalFunctionCall { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    fn external_command_names(input: &str) -> Vec<String> {
        decompose_input(input)
            .iter()
            .filter_map(|u| match u {
                EvalUnit::SimpleCommand { command, .. } => Some(command.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn decompose_top_level_call_before_definition_is_external() {
        // `rm` is called before it is defined — at that point the external `rm`
        // runs, so the call must NOT be an internal call.
        let input = "rm -rf /; rm() { :; }";
        assert!(
            external_command_names(input).contains(&"rm".to_string()),
            "{:?}",
            decompose_input(input)
        );
        assert!(
            !internal_call_names(input).contains(&"rm".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_call_after_unset_f_is_external() {
        let input = "rm() { :; }; unset -f rm; rm -rf /";
        assert!(
            external_command_names(input).contains(&"rm".to_string()),
            "{:?}",
            decompose_input(input)
        );
        assert!(
            !internal_call_names(input).contains(&"rm".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_mutual_recursion_calls_are_internal() {
        // Both defined before the first call (activation point) — body
        // forward-references are established.
        let names = internal_call_names("a() { b; }; b() { a; }; a");
        assert!(names.contains(&"a".to_string()), "{names:?}");
        assert!(names.contains(&"b".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_body_forward_reference_before_definition_is_external() {
        // `g` is invoked before `f` is defined, so the body's `f` runs the
        // external `f`; only the top-level `g` call is internal.
        let input = "g() { f; }; g; f() { :; }";
        assert!(
            internal_call_names(input).contains(&"g".to_string()),
            "{:?}",
            decompose_input(input)
        );
        assert!(
            external_command_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
        assert!(
            !internal_call_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_conditionally_defined_function_does_not_establish() {
        // `f` is defined only inside an `if`; the later top-level call cannot
        // prove it live, so it stays external (conservative).
        let input = "if x; then f() { :; }; fi; f";
        assert!(
            external_command_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
        assert!(
            !internal_call_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_dynamic_unset_clears_live_set() {
        // `unset -f "$x"` could remove anything, so no later call can be proven
        // live.
        let input = "f() { :; }; unset -f \"$x\"; f";
        assert!(
            !internal_call_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_conditional_call_to_established_function_is_internal() {
        // A call inside a conditional to a function defined (and established)
        // beforehand still resolves internal.
        let names = internal_call_names("setup() { :; }; if x; then setup; fi");
        assert!(names.contains(&"setup".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_plain_unset_does_not_affect_functions() {
        // `unset FOO` (no `-f`) touches a variable, not the function, so `f`
        // stays live.
        let names = internal_call_names("f() { :; }; unset FOO; f");
        assert!(names.contains(&"f".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_and_operator_liveness() {
        // `f` defined on the left of `&&`, called on the right — established and
        // internal.
        let names = internal_call_names("f() { :; } && f");
        assert!(names.contains(&"f".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_call_with_redirect_is_still_internal() {
        let names = internal_call_names("f() { :; }; f > /dev/null");
        assert!(names.contains(&"f".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_assignment_prefix_statement_does_not_break_liveness() {
        let names = internal_call_names("x=1; f() { :; }; f");
        assert!(names.contains(&"f".to_string()), "{names:?}");
    }

    #[test]
    fn decompose_conditional_unset_makes_later_call_external() {
        // A possible `unset -f` inside a conditional means the function is no
        // longer *definitely* live afterwards — conservative external.
        let input = "f() { :; }; if x; then unset -f f; fi; f";
        assert!(
            !internal_call_names(input).contains(&"f".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_command_substitution_invocation_caps_establishment() {
        // `$(main)` runs `main` in a subshell BEFORE `wgetx` is defined, so the
        // body's `wgetx` runs the external program. The substitution is an
        // activation point, so `wgetx` (defined later) is not established.
        let input = "main() { wgetx http://evil; }; z=$(main); wgetx() { echo ok; }";
        assert!(
            !internal_call_names(input).contains(&"wgetx".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_backtick_invocation_caps_establishment() {
        let input = "main() { wgetx evil; }; z=`main`; wgetx() { echo ok; }";
        assert!(
            !internal_call_names(input).contains(&"wgetx".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_eval_invocation_caps_establishment() {
        // `eval main` invokes a function via a literal argument (no
        // substitution) — still an activation point.
        let input = "main() { wgetx evil; }; eval main; wgetx() { echo ok; }";
        assert!(
            !internal_call_names(input).contains(&"wgetx".to_string()),
            "{:?}",
            decompose_input(input)
        );
    }

    #[test]
    fn decompose_innocuous_command_does_not_cap_establishment() {
        // A literal command with no substitution and no function invocation does
        // not activate the cluster, so a function defined after it is still
        // established for body calls.
        let names = internal_call_names("f() { :; }; echo start; g() { f; }; main() { g; }; main");
        assert!(names.contains(&"g".to_string()), "{names:?}");
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

    #[test]
    fn decompose_resolves_constant_command_name() {
        let units = decompose_input("BIN=./x; $BIN run");
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::SimpleCommand { command, args, .. }
                    if command == "./x" && args == &["run".to_string()]
            )),
            "expected resolved SimpleCommand, got: {units:?}"
        );
        assert!(
            !units
                .iter()
                .any(|u| matches!(u, EvalUnit::DynamicCommand { .. })),
            "resolved command must not stay dynamic: {units:?}"
        );
    }

    #[test]
    fn decompose_resolves_braced_constant_command_name() {
        let units = decompose_input("BIN=./x; ${BIN} run");
        assert!(
            units.iter().any(|u| matches!(
                u,
                EvalUnit::SimpleCommand { command, .. } if command == "./x"
            )),
            "expected resolved SimpleCommand, got: {units:?}"
        );
    }

    #[test]
    fn decompose_unresolved_variable_command_name_stays_dynamic() {
        let units = decompose_input("$BIN run");
        assert!(
            units
                .iter()
                .any(|u| matches!(u, EvalUnit::DynamicCommand { .. })),
            "expected DynamicCommand, got: {units:?}"
        );
    }
}

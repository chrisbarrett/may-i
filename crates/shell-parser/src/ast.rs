use super::resolve::resolve_param_op;

/// A complete parsed shell command (may contain compound structures).
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Simple(SimpleCommand),
    Pipeline(Vec<Command>),
    And(Box<Command>, Box<Command>),
    Or(Box<Command>, Box<Command>),
    Sequence(Vec<Command>),
    Background(Box<Command>),
    Subshell(Box<Command>),
    BraceGroup(Box<Command>),
    If {
        condition: Box<Command>,
        then_branch: Box<Command>,
        elif_branches: Vec<(Command, Command)>,
        else_branch: Option<Box<Command>>,
    },
    For {
        var: String,
        words: Vec<Word>,
        body: Box<Command>,
    },
    While {
        condition: Box<Command>,
        body: Box<Command>,
    },
    Until {
        condition: Box<Command>,
        body: Box<Command>,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
    },
    FunctionDef {
        name: String,
        body: Box<Command>,
    },
    Redirected {
        command: Box<Command>,
        redirections: Vec<Redirection>,
    },
    Assignment(Assignment),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Option<Command>,
    pub terminator: CaseTerminator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CaseTerminator {
    Break,      // ;;
    Fallthrough, // ;&
    Continue,   // ;;&
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCommand {
    pub assignments: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirections: Vec<Redirection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
}

/// A word is a sequence of word parts that get concatenated.
#[derive(Debug, Clone, PartialEq)]
pub struct Word {
    pub parts: Vec<WordPart>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WordPart {
    Literal(String),
    SingleQuoted(String),
    DoubleQuoted(Vec<WordPart>),
    AnsiCQuoted(String),
    Parameter(String),
    ParameterExpansion(String),
    ParameterExpansionOp { name: String, op: ParameterOperator },
    CommandSubstitution(String),
    Backtick(String),
    Arithmetic(String),
    BraceExpansion(Vec<String>),
    Glob(String),
    ProcessSubstitution { direction: ProcessDirection, command: String },
    /// A safe but opaque value: the variable is trusted but its runtime value
    /// is unknown. The string is a label for diagnostics (e.g. "$f").
    Opaque(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessDirection {
    Input,  // <(cmd)
    Output, // >(cmd)
}

/// Structured representation of parameter expansion operators.
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterOperator {
    Length,                                                        // ${#VAR}
    StripPrefix { longest: bool, pattern: String },                // ${VAR#pat} / ${VAR##pat}
    StripSuffix { longest: bool, pattern: String },                // ${VAR%pat} / ${VAR%%pat}
    Replace { all: bool, pattern: String, replacement: String },   // ${VAR/pat/rep} / ${VAR//pat/rep}
    Default { colon: bool, value: String },                        // ${VAR:-val} / ${VAR-val}
    Alternative { colon: bool, value: String },                    // ${VAR:+val} / ${VAR+val}
    Error { colon: bool, message: String },                        // ${VAR:?msg} / ${VAR?msg}
    Assign { colon: bool, value: String },                         // ${VAR:=val} / ${VAR=val}
    Substring { offset: String, length: Option<String> },          // ${VAR:n} / ${VAR:n:m}
    Uppercase { all: bool },                                       // ${VAR^} / ${VAR^^}
    Lowercase { all: bool },                                       // ${VAR,} / ${VAR,,}
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redirection {
    pub fd: Option<i32>,
    pub kind: RedirectionKind,
    pub target: RedirectionTarget,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectionKind {
    Input,       // <
    Output,      // >
    Append,      // >>
    Clobber,     // >|
    DupInput,    // <&
    DupOutput,   // >&
    Heredoc,     // <<
    HeredocStrip, // <<-
    Herestring,  // <<<
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectionTarget {
    File(Word),
    Fd(i32),
    Heredoc(String),
}

/// If a command substitution contains `cat` fed only by static heredocs
/// (and/or herestrings), the output is fully determined at parse time.
/// Parse the inner command and return the concatenated body if static.
pub(super) fn try_fold_static_cat(cmd: &str) -> Option<String> {
    let ast = super::parse(cmd);
    // Unwrap a Redirected wrapping a Simple command
    // parse() of `cat <<'DELIM'...` always yields Command::Simple
    // because parse_simple_command consumes all redirect tokens inline.
    // Command::Redirected only wraps compound commands (if/for/while/…).
    let sc = match &ast {
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
                RedirectionTarget::Heredoc(text),
            ) => {
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
    assert!(has_heredoc, "unreachable: loop exited without setting has_heredoc");

    // The parser's heredoc body may include a trailing newline;
    // strip it to match the actual output of `cat`.
    let body = body.strip_suffix('\n').unwrap_or(&body).to_string();
    Some(body)
}

/// Abbreviate a string for use in error messages. Multi-line content is
/// reduced to the first line with "…" appended; long single lines are
/// truncated at 60 chars.
pub fn abbreviate(s: &str) -> String {
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

/// Format a parameter expansion operator back to shell syntax (without `${` and `}`).
pub(super) fn format_param_op(name: &str, op: &ParameterOperator) -> String {
    match op {
        ParameterOperator::Length => format!("#{name}"),
        ParameterOperator::StripPrefix { longest, pattern } => {
            if *longest { format!("{name}##{pattern}") } else { format!("{name}#{pattern}") }
        }
        ParameterOperator::StripSuffix { longest, pattern } => {
            if *longest { format!("{name}%%{pattern}") } else { format!("{name}%{pattern}") }
        }
        ParameterOperator::Replace { all, pattern, replacement } => {
            if *all {
                format!("{name}//{pattern}/{replacement}")
            } else {
                format!("{name}/{pattern}/{replacement}")
            }
        }
        ParameterOperator::Default { colon, value } => {
            if *colon { format!("{name}:-{value}") } else { format!("{name}-{value}") }
        }
        ParameterOperator::Alternative { colon, value } => {
            if *colon { format!("{name}:+{value}") } else { format!("{name}+{value}") }
        }
        ParameterOperator::Error { colon, message } => {
            if *colon { format!("{name}:?{message}") } else { format!("{name}?{message}") }
        }
        ParameterOperator::Assign { colon, value } => {
            if *colon { format!("{name}:={value}") } else { format!("{name}={value}") }
        }
        ParameterOperator::Substring { offset, length } => {
            match length {
                Some(len) => format!("{name}:{offset}:{len}"),
                None => format!("{name}:{offset}"),
            }
        }
        ParameterOperator::Uppercase { all } => {
            if *all { format!("{name}^^") } else { format!("{name}^") }
        }
        ParameterOperator::Lowercase { all } => {
            if *all { format!("{name},,") } else { format!("{name},") }
        }
    }
}

/// Returns true if any part in the slice is a dynamic shell construct.
/// Opaque parts are safe (trusted) and do NOT count as dynamic.
fn has_dynamic_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::CommandSubstitution(_)
        | WordPart::Backtick(_)
        | WordPart::Parameter(_)
        | WordPart::ParameterExpansion(_)
        | WordPart::ParameterExpansionOp { .. }
        | WordPart::Arithmetic(_)
        | WordPart::ProcessSubstitution { .. } => true,
        WordPart::DoubleQuoted(inner) => has_dynamic_in(inner),
        WordPart::Opaque(_) => false,
        _ => false,
    })
}

/// Collect human-readable descriptions of dynamic parts from a part slice.
fn collect_dynamic_from(parts: &[WordPart], out: &mut Vec<String>) {
    for part in parts {
        match part {
            WordPart::Parameter(name) => out.push(format!("${name}")),
            WordPart::ParameterExpansion(name) => out.push(format!("${{{name}}}")),
            WordPart::CommandSubstitution(cmd) => {
                out.push(format!("$({})", abbreviate(cmd)));
            }
            WordPart::Backtick(cmd) => {
                out.push(format!("`{}`", abbreviate(cmd)));
            }
            WordPart::Arithmetic(expr) => {
                out.push(format!("$(({}))", abbreviate(expr)));
            }
            WordPart::ProcessSubstitution { direction, command } => {
                let sigil = match direction {
                    ProcessDirection::Input => '<',
                    ProcessDirection::Output => '>',
                };
                out.push(format!("{sigil}({})", abbreviate(command)));
            }
            WordPart::ParameterExpansionOp { name, op } => {
                out.push(format!("${{{}}}", format_param_op(name, op)));
            }
            WordPart::DoubleQuoted(inner) => {
                collect_dynamic_from(inner, out);
            }
            WordPart::Opaque(_) => {} // safe, not dynamic
            _ => {}
        }
    }
}

/// Flatten a slice of word parts to a plain string.
fn parts_to_str(parts: &[WordPart], out: &mut String) {
    for part in parts {
        match part {
            WordPart::Literal(s)
            | WordPart::SingleQuoted(s)
            | WordPart::AnsiCQuoted(s)
            | WordPart::Parameter(s)
            | WordPart::ParameterExpansion(s)
            | WordPart::CommandSubstitution(s)
            | WordPart::Backtick(s)
            | WordPart::Arithmetic(s)
            | WordPart::Glob(s) => out.push_str(s),
            WordPart::ParameterExpansionOp { name, op } => {
                out.push_str(&format_param_op(name, op));
            }
            WordPart::DoubleQuoted(inner) => {
                parts_to_str(inner, out);
            }
            WordPart::BraceExpansion(items) => {
                out.push_str(&items.join(","));
            }
            WordPart::ProcessSubstitution { command, .. } => {
                out.push_str(command);
            }
            WordPart::Opaque(label) => {
                out.push_str(label);
            }
        }
    }
}

impl Word {
    pub fn literal(s: &str) -> Self {
        Word {
            parts: vec![WordPart::Literal(s.to_string())],
        }
    }

    /// Returns true if this word contains dynamic shell constructs whose runtime
    /// value cannot be determined by static analysis.
    pub fn has_dynamic_parts(&self) -> bool {
        has_dynamic_in(&self.parts)
    }

    /// Collect human-readable descriptions of the dynamic parts in this word.
    /// Returns items like `"$HOME"`, `"$(whoami)"`, `` "`cmd`" ``, `"$((x+1))"`.
    pub fn dynamic_parts(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_dynamic_from(&self.parts, &mut out);
        out
    }

    /// Resolve known environment variables, replacing `Parameter` and
    /// `ParameterExpansion` parts with `Literal` when the variable name is in `env`.
    /// Also resolves `ParameterExpansionOp` by applying the operator to the value.
    /// Other dynamic parts (command substitution, backticks, etc.) are left as-is.
    pub fn resolve(&self, env: &std::collections::HashMap<String, String>) -> Word {
        Word {
            parts: resolve_parts(&self.parts, env),
        }
    }

    /// Flatten this word to a plain string for matching purposes.
    pub fn to_str(&self) -> String {
        let mut out = String::new();
        parts_to_str(&self.parts, &mut out);
        out
    }

    /// Returns true if this word contains any opaque parts.
    pub fn has_opaque_parts(&self) -> bool {
        has_opaque_in(&self.parts)
    }

    /// Returns true if all parts are static (Literal/SingleQuoted/AnsiCQuoted).
    pub fn is_literal(&self) -> bool {
        !has_dynamic_in(&self.parts) && !has_opaque_in(&self.parts)
    }

}

/// Returns true if any part in the slice is an Opaque value.
fn has_opaque_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::Opaque(_) => true,
        WordPart::DoubleQuoted(inner) => has_opaque_in(inner),
        _ => false,
    })
}

/// Resolve environment variables in a slice of word parts.
fn resolve_parts(
    parts: &[WordPart],
    env: &std::collections::HashMap<String, String>,
) -> Vec<WordPart> {
    parts.iter().map(|part| match part {
        WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => {
            if let Some(val) = env.get(name.as_str()) {
                WordPart::Literal(val.clone())
            } else {
                part.clone()
            }
        }
        WordPart::ParameterExpansionOp { name, op } => {
            resolve_param_op(name, op, env)
        }
        WordPart::DoubleQuoted(inner) => {
            WordPart::DoubleQuoted(resolve_parts(inner, env))
        }
        _ => part.clone(),
    }).collect()
}

impl Command {
    /// Returns all direct child commands of this node.
    pub fn children(&self) -> Vec<&Command> {
        match self {
            Command::Simple(_) | Command::Assignment(_) => vec![],
            Command::Pipeline(cmds) | Command::Sequence(cmds) => cmds.iter().collect(),
            Command::And(a, b) | Command::Or(a, b) => vec![a, b],
            Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => vec![c],
            Command::If { condition, then_branch, elif_branches, else_branch } => {
                let mut children = vec![condition.as_ref(), then_branch.as_ref()];
                for (cond, body) in elif_branches {
                    children.push(cond);
                    children.push(body);
                }
                if let Some(eb) = else_branch {
                    children.push(eb);
                }
                children
            }
            Command::For { body, .. } => vec![body],
            Command::While { condition, body } | Command::Until { condition, body } => {
                vec![condition, body]
            }
            Command::Case { arms, .. } => {
                arms.iter().filter_map(|arm| arm.body.as_ref()).collect()
            }
            Command::FunctionDef { body, .. } => vec![body],
            Command::Redirected { command, .. } => vec![command],
        }
    }
}

impl SimpleCommand {
    /// The command name (first word), if any.
    pub fn command_name(&self) -> Option<&str> {
        self.words.first().map(|w| {
            // Return a reference to the first literal part
            if let Some(WordPart::Literal(s)) = w.parts.first() {
                s.as_str()
            } else {
                ""
            }
        })
    }

    /// Resolve known environment variables in all words, assignment values,
    /// and redirect file targets.
    pub fn resolve(&self, env: &std::collections::HashMap<String, String>) -> SimpleCommand {
        SimpleCommand {
            assignments: self.assignments.iter().map(|a| Assignment {
                name: a.name.clone(),
                value: a.value.resolve(env),
            }).collect(),
            words: self.words.iter().map(|w| w.resolve(env)).collect(),
            redirections: self.redirections.iter().map(|r| Redirection {
                fd: r.fd,
                kind: r.kind.clone(),
                target: match &r.target {
                    RedirectionTarget::File(w) => RedirectionTarget::File(w.resolve(env)),
                    other => other.clone(),
                },
            }).collect(),
        }
    }

    /// Apply a transform to every Word in assignments, command words, and
    /// file-redirect targets, returning a new SimpleCommand.
    pub fn map_words(&self, f: impl Fn(&Word) -> Word) -> SimpleCommand {
        SimpleCommand {
            assignments: self.assignments.iter().map(|a| Assignment {
                name: a.name.clone(),
                value: f(&a.value),
            }).collect(),
            words: self.words.iter().map(&f).collect(),
            redirections: self.redirections.iter().map(|r| Redirection {
                fd: r.fd,
                kind: r.kind.clone(),
                target: match &r.target {
                    RedirectionTarget::File(w) => RedirectionTarget::File(f(w)),
                    other => other.clone(),
                },
            }).collect(),
        }
    }

    /// The arguments (all words after the first).
    pub fn args(&self) -> &[Word] {
        if self.words.len() > 1 {
            &self.words[1..]
        } else {
            &[]
        }
    }

}

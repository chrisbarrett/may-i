use serde::Serialize;

use crate::diagnostic::Span;

mod command;
mod helpers;
mod word;

pub(crate) use helpers::abbreviate;
pub(crate) use helpers::format_param_op;
pub(super) use helpers::try_fold_static_cat;

/// A complete parsed shell command (may contain compound structures).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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
    Loop {
        kind: LoopKind,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopKind {
    While,
    Until,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Option<Command>,
    pub terminator: CaseTerminator,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseTerminator {
    Break,       // ;;
    Fallthrough, // ;&
    Continue,    // ;;&
}

#[derive(Clone, PartialEq, Serialize)]
pub struct SimpleCommand {
    pub assignments: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirections: Vec<Redirection>,
    /// Byte range in the original input covering this simple command
    /// (assignments + words + redirections). Empty span (0, 0) when the
    /// AST node was constructed without a source — e.g. by tests or by
    /// the empty-input fallback in `parse_complete`.
    #[serde(skip)]
    pub span: Span,
}

// Hand-rolled to keep `span` out of Debug output so AST snapshots stay
// stable — `span` is byte offsets that are observable through other tests.
impl std::fmt::Debug for SimpleCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleCommand")
            .field("assignments", &self.assignments)
            .field("words", &self.words)
            .field("redirections", &self.redirections)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
}

/// A word is a sequence of word parts that get concatenated.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Word {
    pub parts: Vec<WordPart>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WordPart {
    Literal(String),
    SingleQuoted(String),
    DoubleQuoted(Vec<WordPart>),
    AnsiCQuoted(String),
    Parameter(String),
    ParameterExpansion(String),
    ParameterExpansionOp {
        name: String,
        op: ParameterOperator,
    },
    CommandSubstitution(String),
    Backtick(String),
    Arithmetic(String),
    BraceExpansion(Vec<String>),
    Glob(String),
    ProcessSubstitution {
        direction: ProcessDirection,
        command: String,
    },
    /// A safe but opaque value: the variable is trusted but its runtime value
    /// is unknown. The string is a label for diagnostics (e.g. "$f").
    Opaque(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessDirection {
    Input,  // <(cmd)
    Output, // >(cmd)
}

/// Structured representation of parameter expansion operators.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParameterOperator {
    Length, // ${#VAR}
    StripPrefix {
        longest: bool,
        pattern: String,
    }, // ${VAR#pat} / ${VAR##pat}
    StripSuffix {
        longest: bool,
        pattern: String,
    }, // ${VAR%pat} / ${VAR%%pat}
    Replace {
        all: bool,
        pattern: String,
        replacement: String,
    }, // ${VAR/pat/rep} / ${VAR//pat/rep}
    Default {
        colon: bool,
        value: String,
    }, // ${VAR:-val} / ${VAR-val}
    Alternative {
        colon: bool,
        value: String,
    }, // ${VAR:+val} / ${VAR+val}
    Error {
        colon: bool,
        message: String,
    }, // ${VAR:?msg} / ${VAR?msg}
    Assign {
        colon: bool,
        value: String,
    }, // ${VAR:=val} / ${VAR=val}
    Substring {
        offset: String,
        length: Option<String>,
    }, // ${VAR:n} / ${VAR:n:m}
    Uppercase {
        all: bool,
    }, // ${VAR^} / ${VAR^^}
    Lowercase {
        all: bool,
    }, // ${VAR,} / ${VAR,,}
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Redirection {
    pub fd: Option<i32>,
    pub kind: RedirectionKind,
    pub target: RedirectionTarget,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectionKind {
    Input,        // <
    Output,       // >
    Append,       // >>
    Clobber,      // >|
    DupInput,     // <&
    DupOutput,    // >&
    Heredoc,      // <<
    HeredocStrip, // <<-
    Herestring,   // <<<
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectionTarget {
    File(Word),
    Fd(i32),
    Heredoc(String),
}

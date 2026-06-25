use serde::Serialize;

use crate::diagnostic::Span;

mod command;
mod helpers;
mod word;

pub(crate) use helpers::abbreviate;
pub(crate) use helpers::format_array_expansion;
pub(crate) use helpers::format_param_op;
pub(super) use helpers::try_fold_static_cat;
pub use word::{Embedded, SubstitutionForm};

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
    pub value: AssignmentValue,
}

/// The right-hand side of an assignment: a scalar word (`x=foo`) or an array
/// literal (`x=(a b c)`). Modelling the two as one type lets every
/// assignment-handling consumer match on the value kind rather than juggle two
/// assignment nodes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AssignmentValue {
    /// A scalar right-hand side, e.g. `x=foo` or `x=$(cmd)`. Empty value
    /// (`x=`) is a `Scalar` whose word is an empty literal.
    Scalar(Word),
    /// An array literal, e.g. `x=(a b c)` or `declare -A m=([k]=v)`. Preserves
    /// each element word and records whether the array is indexed or
    /// associative (see [`ArrayKind`]).
    Array {
        array_kind: ArrayKind,
        elements: Vec<Word>,
    },
}

/// Whether a bash array is indexed (integer keys, defined order) or
/// associative (string keys, *unspecified* element order). The follow-on
/// resolver relies on this distinction: resolving `"${arr[@]}"` to a definite
/// argv order is sound for an indexed array but not an associative one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArrayKind {
    /// `declare -a`, `local -a`, `export -a`, or a bare `name=(…)`.
    Indexed,
    /// `declare -A` / `local -A` / `export -A`.
    Associative,
}

impl AssignmentValue {
    /// Borrow the scalar word, if this value is a scalar. Convenience for the
    /// many consumers that only ever handled the historical scalar form; the
    /// array arm returns `None` and must be handled explicitly where it
    /// matters.
    pub fn as_scalar(&self) -> Option<&Word> {
        match self {
            AssignmentValue::Scalar(w) => Some(w),
            AssignmentValue::Array { .. } => None,
        }
    }

    /// Every word this value carries: the single scalar word, or each array
    /// element word. Used by consumers that walk assignment words for embedded
    /// substitutions and env-read taint uniformly across both forms.
    pub fn words(&self) -> &[Word] {
        match self {
            AssignmentValue::Scalar(w) => std::slice::from_ref(w),
            AssignmentValue::Array { elements, .. } => elements,
        }
    }
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
    /// A subscripted array reference inside `${…}`: `${arr[0]}`, `${arr[@]}`,
    /// `${arr[*]}`, and the length form `${#arr[@]}`. The array `name` and the
    /// `subscript` are kept distinct rather than folded into the name string,
    /// so the resolver can recognise and resolve it. `length` is set for the
    /// `${#name[subscript]}` form.
    ///
    /// Against a provably-constant **indexed** array, the single-value forms
    /// `${arr[i]}` and `${#arr[@]}` resolve through `Word::resolve`, and a quoted
    /// `"${arr[@]}"` splices to one argv word per element during argv
    /// construction (engine `decompose`). The IFS-dependent forms (`${arr[*]}`,
    /// unquoted `${arr[@]}`) and any non-constant array stay expansion-bearing
    /// (unresolved).
    ArrayExpansion {
        name: String,
        subscript: Subscript,
        /// `${#arr[@]}` — the element-count form.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        length: bool,
    },
    ParameterExpansionOp {
        name: String,
        op: ParameterOperator,
        /// Command and backtick substitutions lexed out of the operator's
        /// expandable operands (`${x:-$(cmd)}`, `${x#$(cmd)}`, …). Bash runs
        /// these, so they are captured here as structured parts — each carrying
        /// its source-byte span — for the engine to gate. The `op` fields keep
        /// the verbatim operand text for resolution and display; this field is
        /// purely additive and is empty for operands with no substitution.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        embedded: Vec<WordPart>,
    },
    CommandSubstitution {
        source: String,
        span: Span,
    },
    Backtick {
        source: String,
        span: Span,
    },
    Arithmetic {
        source: String,
        span: Span,
    },
    BraceExpansion(Vec<String>),
    Glob(String),
    ProcessSubstitution {
        direction: ProcessDirection,
        command: String,
        span: Span,
    },
    /// A safe but opaque value: the variable is trusted but its runtime value
    /// is unknown. The string is a label for diagnostics (e.g. "$f").
    Opaque(String),
}

/// The subscript of a [`WordPart::ArrayExpansion`]. `Index` carries the
/// subscript word, which may itself be dynamic (`${arr[$i]}`); `All` is `@`
/// and `Star` is `*`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "subscript")]
pub enum Subscript {
    Index(Word),
    All,
    Star,
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
    /// `${VAR^pat}` / `${VAR^^pat}` / `${VAR,pat}` / `${VAR,,pat}` — case
    /// conversion restricted to characters matching `pattern`. Unlike the
    /// pattern-less `Uppercase`/`Lowercase`, this is **never resolved** (bash
    /// converts only matching chars, diverging from a full-case fold), but the
    /// pattern is kept structured so a substitution buried in it is gated.
    CaseConvert {
        upper: bool,
        all: bool,
        pattern: String,
    },
    /// `${VAR@op}` — a parameter transformation (`@Q`, `@a`, `@P`, …). Never
    /// resolved; `spec` is the operator text after `@`, kept for display and so
    /// a substitution in it is carried in `embedded`.
    Transform {
        spec: String,
    },
    /// An operator the lexer does not structure (`${VAR.foo}` and other junk).
    /// Never resolved; `source` is the verbatim text after the name, kept for
    /// display fidelity and substitution gating.
    Unknown {
        source: String,
    },
    /// Indirect / nameref expansion `${!name}`, `${!prefix*}`, `${!arr[@]}`.
    /// The variable read is named *indirectly* by the operand, so the operand
    /// is not itself a read of that literal name. Never resolved. The enclosing
    /// `ParameterExpansionOp.name` is empty for this form (there is no direct
    /// read); `operand` carries the text after `!` for display, and `listing`
    /// records the shape.
    Indirect {
        operand: String,
        listing: NameListing,
    },
}

/// The shape of an indirect/nameref expansion `${!…}`. All variants stay
/// unresolved; the distinction is retained for display fidelity and to record
/// intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameListing {
    /// `${!name}` — the value of the variable *named by* `$name`.
    Indirect,
    /// `${!prefix*}` / `${!prefix@}` — the names of variables sharing a prefix.
    Prefix,
    /// `${!arr[@]}` / `${!arr[*]}` — the keys/indices of an array.
    Keys,
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
    Heredoc {
        body: String,
        /// Whether the opening delimiter was quoted (`<<'EOF'`, `<<"EOF"`,
        /// `<<\EOF`). A quoted delimiter suppresses every expansion in the
        /// body; an unquoted one (`<<EOF`) leaves parameter, command, and
        /// arithmetic expansion live.
        quoted: bool,
        /// Embedded command/arithmetic substitutions found in an unquoted
        /// body, with inner-spans into the original input. Always empty for
        /// a quoted heredoc. Process substitution is excluded — bash does
        /// not perform it in heredoc bodies.
        substitutions: Vec<WordPart>,
    },
}

//! Semantic styling roles (color-as-data).
//!
//! [`Style`] is a closed set of *semantic roles*, not structural colour. A
//! styled fragment carries a role; the sole role→SGR mapping lives in the
//! `may-i-output` renderer, which also owns the `NO_COLOR`/`--color` decision.
//! Roles mirror what content-class colouring (`colorize_atom`) already did
//! (keyword, string-literal, form-head) plus the decoration roles the trace,
//! check, and advisory surfaces require.
//!
//! `Style` lives in `pp` (not `may-i-output`) because the dependency graph is
//! `may-i-output → pp → core`: the pretty-printer in `pp` must *emit* roles, so
//! the enum sits where `pp` can name it; `may-i-output` re-exports it.

/// A semantic styling role. The renderer maps each to an SGR sequence at one
/// site; with colour disabled every role renders as plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Style {
    /// No styling.
    Plain,
    /// Chrome and labels (dividers, field labels, the `$` sigil, `→` arrows).
    Dimmed,
    /// Bold, no colour (command text, section headings, counts).
    Strong,
    /// Italic, no colour (input-derived detail in trace decorations).
    Emphasis,
    /// A `:keyword` atom.
    Keyword,
    /// A `"string"` or `#"regex"` literal atom.
    StringLit,
    /// A recognised form head (`rule`, `command`, `when`, …).
    FormHead,
    /// An affirmative decision/result: `:allow`, `yes`, `✓`, `PASS` (green, bold).
    Allow,
    /// An affirmative result without bold: summary `✓` (green).
    AllowSoft,
    /// An ask decision/result: `:ask`, `?`, `warning` (yellow, bold). Also the
    /// warn-level note heading/icon.
    Ask,
    /// An ask result without bold: `no`, `missing` (yellow).
    AskSoft,
    /// An ask decoration in italic: the "No matching rule" trace label
    /// (yellow, italic).
    AskEmphasis,
    /// A deny decision/result: `:deny`, `✗`, `error`, `FAIL` (red, bold). Also
    /// the error-level note heading/icon.
    Deny,
    /// A deny result without bold: summary `✗` (red).
    DenySoft,
    /// The info-level note heading/icon (blue, bold).
    Info,
    /// An accent for file paths and carrier names (cyan).
    Accent,
    /// The `may-i eval` command echo, coloured by decision (underlined).
    EchoAllow,
    /// As [`Style::EchoAllow`] for an ask decision.
    EchoAsk,
    /// As [`Style::EchoAllow`] for a deny decision.
    EchoDeny,
}

/// Classify a pretty-printer atom by its content, returning the role that
/// content-class colouring assigns it. This is the role-valued successor to
/// `colorize_atom`'s branching.
#[must_use]
pub fn atom_style(s: &str) -> Style {
    if s.starts_with(':') {
        Style::Keyword
    } else if s.starts_with('"') || s.starts_with("#\"") {
        Style::StringLit
    } else if is_form_head(s) {
        Style::FormHead
    } else {
        Style::Plain
    }
}

const FORM_HEADS: &[&str] = &[
    "rule",
    "command",
    "args",
    "effect",
    "cond",
    "if",
    "when",
    "unless",
    "else",
    "positional",
    "exact",
    "anywhere",
    "define",
    "check",
    "with-facts",
];

fn is_form_head(s: &str) -> bool {
    FORM_HEADS.contains(&s)
}

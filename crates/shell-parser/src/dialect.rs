/// The shell dialect a command is judged against.
///
/// The dialect selects which grammar an input is parsed under. It governs
/// only which constructs are *well-formed*; a construct well-formed in both
/// dialects is represented identically in the AST. zsh has no published
/// formal grammar, so [`Dialect::Zsh`] is defined as bash plus an explicit,
/// enumerated set of additional accepted constructs (no-semicolon brace
/// terminators and glob qualifiers). Any construct not in that set behaves
/// under zsh exactly as it does under bash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// The bash grammar. The default, and the only dialect `check` uses.
    #[default]
    Bash,
    /// The zsh grammar: bash plus the enumerated zsh-only constructs.
    Zsh,
}

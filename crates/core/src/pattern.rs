// Argument and command patterns for the unified rule DSL.

use crate::Quantifier;
use crate::ast::Effect;
use crate::types::Expr;

/// Pattern for matching commands in rules.
/// Position 1 of a rule is always the command pattern.
#[derive(Debug, Clone)]
pub enum CommandPattern {
    /// Exact command name match.
    Literal(String),

    /// Regex pattern match.
    Regex(regex::Regex),

    /// Matches any of the given command names.
    Or(Vec<CommandPattern>),
}

impl CommandPattern {
    /// Check if a command name matches this pattern.
    pub fn is_match(&self, command: &str) -> bool {
        match self {
            CommandPattern::Literal(lit) => lit == command,
            CommandPattern::Regex(re) => re.is_match(command),
            CommandPattern::Or(patterns) => patterns.iter().any(|p| p.is_match(command)),
        }
    }
}

/// A positional argument with quantifier.
#[derive(Debug, Clone)]
pub struct PositionalArg {
    pub quantifier: Quantifier,
    pub pattern: Expr<Effect>,
    /// Optional recursive evaluation target for remaining args.
    pub recursive: bool,
}

impl PositionalArg {
    /// Create a single required positional argument.
    pub fn one(expr: Expr<Effect>) -> Self {
        Self {
            quantifier: Quantifier::One,
            pattern: expr,
            recursive: false,
        }
    }

    /// Create a positional argument with custom quantifier.
    pub fn with_quantifier(expr: Expr<Effect>, quantifier: Quantifier) -> Self {
        Self {
            quantifier,
            pattern: expr,
            recursive: false,
        }
    }

    /// Mark this argument as the recursive evaluation target.
    pub fn recursive(mut self) -> Self {
        self.recursive = true;
        self
    }
}

/// Pattern for matching command arguments.
#[derive(Debug, Clone)]
pub enum ArgPattern {
    /// Match positional args by position (skip flags).
    /// Syntax: `(positional PATTERN ... [. EFFECT])`
    Positional {
        patterns: Vec<PositionalArg>,
        /// Optional continuation effect evaluated with remaining args.
        continuation: Option<Box<crate::ast::Effect>>,
    },

    /// Like Positional, but requires exactly as many positional args as patterns.
    /// Syntax: `(exact PATTERN ... [. EFFECT])`
    Exact {
        patterns: Vec<PositionalArg>,
        /// Optional continuation effect evaluated with remaining args.
        continuation: Option<Box<crate::ast::Effect>>,
    },

    /// Token appears anywhere in argv.
    /// Syntax: `(anywhere PATTERN ...)`
    Anywhere(Vec<Expr<Effect>>),

    /// Token must NOT appear anywhere in argv.
    /// Syntax: `(forbidden PATTERN ...)`
    Forbidden(Vec<Expr<Effect>>),

    /// Match a literal string at a specific position (1-indexed).
    /// Syntax: `(= N PATTERN)`
    At {
        position: usize,
        pattern: Expr<Effect>,
    },
}

impl ArgPattern {
    /// Create a simple positional pattern from expressions.
    pub fn positional(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Positional {
            patterns: exprs.into_iter().map(PositionalArg::one).collect(),
            continuation: None,
        }
    }

    /// Create a positional pattern with a continuation effect.
    pub fn positional_with_continuation(
        exprs: Vec<Expr<Effect>>,
        continuation: crate::ast::Effect,
    ) -> Self {
        ArgPattern::Positional {
            patterns: exprs.into_iter().map(PositionalArg::one).collect(),
            continuation: Some(Box::new(continuation)),
        }
    }

    /// Create an exact positional pattern from expressions.
    pub fn exact(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Exact {
            patterns: exprs.into_iter().map(PositionalArg::one).collect(),
            continuation: None,
        }
    }

    /// Create an exact pattern with a continuation effect.
    pub fn exact_with_continuation(
        exprs: Vec<Expr<Effect>>,
        continuation: crate::ast::Effect,
    ) -> Self {
        ArgPattern::Exact {
            patterns: exprs.into_iter().map(PositionalArg::one).collect(),
            continuation: Some(Box::new(continuation)),
        }
    }

    /// Create an anywhere pattern.
    pub fn anywhere(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Anywhere(exprs)
    }

    /// Create a forbidden pattern.
    pub fn forbidden(exprs: Vec<Expr<Effect>>) -> Self {
        ArgPattern::Forbidden(exprs)
    }

    /// Create an at-position pattern.
    pub fn at(position: usize, pattern: Expr<Effect>) -> Self {
        ArgPattern::At { position, pattern }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Expr;

    #[test]
    fn command_pattern_literal_matches_exactly() {
        let pattern = CommandPattern::Literal("git".into());
        assert!(pattern.is_match("git"));
        assert!(!pattern.is_match("hub"));
    }

    #[test]
    fn command_pattern_regex_matches_pattern() {
        let pattern = CommandPattern::Regex(regex::Regex::new("^git.*").unwrap());
        assert!(pattern.is_match("git"));
        assert!(pattern.is_match("github"));
        assert!(!pattern.is_match("hub"));
    }

    #[test]
    fn command_pattern_or_matches_any() {
        let pattern = CommandPattern::Or(vec![
            CommandPattern::Literal("git".into()),
            CommandPattern::Literal("hub".into()),
        ]);
        assert!(pattern.is_match("git"));
        assert!(pattern.is_match("hub"));
        assert!(!pattern.is_match("svn"));
    }

    #[test]
    fn positional_arg_one_creates_required() {
        let arg = PositionalArg::one(Expr::Literal("test".into()));
        assert!(matches!(arg.quantifier, Quantifier::One));
        assert!(!arg.recursive);
    }

    #[test]
    fn positional_arg_with_quantifier_sets_correctly() {
        let arg = PositionalArg::with_quantifier(Expr::Wildcard, Quantifier::Optional);
        assert!(matches!(arg.quantifier, Quantifier::Optional));
    }

    #[test]
    fn positional_arg_recursive_marks_correctly() {
        let arg = PositionalArg::one(Expr::Wildcard).recursive();
        assert!(arg.recursive);
    }

    #[test]
    fn arg_pattern_positional_creates_correctly() {
        let pattern =
            ArgPattern::positional(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        assert!(
            matches!(pattern, ArgPattern::Positional { patterns, continuation: None } if patterns.len() == 2)
        );
    }

    #[test]
    fn arg_pattern_exact_creates_correctly() {
        let pattern = ArgPattern::exact(vec![Expr::Literal("x".into())]);
        assert!(
            matches!(pattern, ArgPattern::Exact { patterns, continuation: None } if patterns.len() == 1)
        );
    }

    #[test]
    fn arg_pattern_anywhere_creates_correctly() {
        let pattern = ArgPattern::anywhere(vec![Expr::Literal("--flag".into())]);
        assert!(matches!(pattern, ArgPattern::Anywhere(exprs) if exprs.len() == 1));
    }

    #[test]
    fn arg_pattern_forbidden_creates_correctly() {
        let pattern = ArgPattern::forbidden(vec![Expr::Literal("--dangerous".into())]);
        assert!(matches!(pattern, ArgPattern::Forbidden(exprs) if exprs.len() == 1));
    }

    #[test]
    fn arg_pattern_at_creates_correctly() {
        let pattern = ArgPattern::at(2, Expr::Literal("file.txt".into()));
        assert!(matches!(pattern, ArgPattern::At { position: 2, .. }));
    }

    #[test]
    fn positional_with_continuation_sets_continuation() {
        let cont = Effect::allow(None);
        let pattern = ArgPattern::positional_with_continuation(vec![], cont);
        assert!(
            matches!(pattern, ArgPattern::Positional { continuation: Some(_), patterns } if patterns.is_empty())
        );
    }

    #[test]
    fn positional_with_continuation_with_patterns() {
        let cont = Effect::ask(Some("confirm".into()));
        let pattern = ArgPattern::positional_with_continuation(
            vec![Expr::Literal("arg1".into()), Expr::Literal("arg2".into())],
            cont,
        );
        assert!(
            matches!(pattern, ArgPattern::Positional { continuation: Some(_), patterns } if patterns.len() == 2)
        );
    }

    #[test]
    fn exact_with_continuation_sets_continuation() {
        let cont = Effect::deny(Some("blocked".into()));
        let pattern = ArgPattern::exact_with_continuation(vec![], cont);
        assert!(
            matches!(pattern, ArgPattern::Exact { continuation: Some(_), patterns } if patterns.is_empty())
        );
    }

    #[test]
    fn exact_with_continuation_with_patterns() {
        let cont = Effect::allow(Some("safe".into()));
        let pattern = ArgPattern::exact_with_continuation(vec![Expr::Literal("cmd".into())], cont);
        assert!(
            matches!(pattern, ArgPattern::Exact { continuation: Some(_), patterns } if patterns.len() == 1)
        );
    }
}

// Core AST types for the unified rule DSL.

use crate::span::Span;
use crate::types::Decision;
use crate::v2::pattern::{ArgPattern, CommandPattern};
use crate::v2::predicate::Predicate;

/// A value with source span tracking.
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    /// Create a new spanned value.
    pub fn new(value: T, span: Span) -> Self {
        Self { value, span }
    }

    /// Map over the inner value, preserving the span.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Spanned<U> {
        Spanned {
            value: f(self.value),
            span: self.span,
        }
    }
}

/// Authorization effect: a decision with optional message and recursive evaluation.
#[derive(Debug, Clone)]
pub enum Effect {
    /// Allow the command.
    /// Syntax: `(effect :allow)` or `(effect :allow "reason")`
    Allow(Option<String>),

    /// Ask for confirmation.
    /// Syntax: `(effect :ask)` or `(effect :ask "reason")`
    Ask(Option<String>),

    /// Deny the command.
    /// Syntax: `(effect :deny)` or `(effect :deny "reason")`
    Deny(Option<String>),

    /// Recursively evaluate an inner command.
    /// Syntax: `(may-i PATTERN)`
    Evaluate(ArgPattern),

    /// Branch on predicates: first matching branch wins.
    /// Syntax: `(case [(PREDICATE EFFECT) ...] [ELSE-EFFECT])`
    Case {
        branches: Vec<(Spanned<Predicate>, Spanned<Effect>)>,
        fallback: Option<Box<Spanned<Effect>>>,
    },

    /// Conditional effect: applies only when predicate is true.
    /// Sugar form preserved for trace output.
    /// Syntax: `(when PREDICATE EFFECT)`
    When {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Conditional effect: applies only when predicate is false.
    /// Sugar form preserved for trace output.
    /// Syntax: `(unless PREDICATE EFFECT)`
    Unless {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Conditional effect with both then and else branches.
    /// Sugar form preserved for trace output.
    /// Syntax: `(if PREDICATE THEN-EFFECT [ELSE-EFFECT])`
    If {
        predicate: Spanned<Predicate>,
        then_effect: Box<Spanned<Effect>>,
        else_effect: Option<Box<Spanned<Effect>>>,
    },
}

impl Effect {
    /// Create an allow effect.
    pub fn allow(reason: Option<String>) -> Self {
        Effect::Allow(reason)
    }

    /// Create an ask effect.
    pub fn ask(reason: Option<String>) -> Self {
        Effect::Ask(reason)
    }

    /// Create a deny effect.
    pub fn deny(reason: Option<String>) -> Self {
        Effect::Deny(reason)
    }

    /// Create a recursive evaluation effect.
    pub fn evaluate(pattern: ArgPattern) -> Self {
        Effect::Evaluate(pattern)
    }

    /// Get the terminal decision if this is a terminal effect.
    pub fn terminal_decision(&self) -> Option<Decision> {
        match self {
            Effect::Allow(_) => Some(Decision::Allow),
            Effect::Ask(_) => Some(Decision::Ask),
            Effect::Deny(_) => Some(Decision::Deny),
            _ => None,
        }
    }

    /// Check if this is a terminal effect (Allow, Ask, or Deny).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Effect::Allow(_) | Effect::Ask(_) | Effect::Deny(_))
    }

    /// Check if this is a sugar form (When, Unless, If).
    pub fn is_sugar(&self) -> bool {
        matches!(
            self,
            Effect::When { .. } | Effect::Unless { .. } | Effect::If { .. }
        )
    }
}

/// A named predicate definition.
/// Syntax: `(define NAME PREDICATE)`
#[derive(Debug, Clone)]
pub struct Define {
    /// The name of the predicate.
    pub name: String,

    /// The predicate body.
    pub predicate: Spanned<Predicate>,

    /// Source span for error reporting.
    pub span: Span,
}

impl Define {
    /// Create a new named predicate definition.
    pub fn new(name: impl Into<String>, predicate: Spanned<Predicate>, span: Span) -> Self {
        Self {
            name: name.into(),
            predicate,
            span,
        }
    }
}

/// An authorization rule.
/// Syntax: `(rule COMMAND-PREDICATE PREDICATE* EFFECT)`
#[derive(Debug, Clone)]
pub struct Rule {
    /// The command pattern (position 1 of the rule).
    pub command: Spanned<CommandPattern>,

    /// Additional predicates that must all match.
    pub predicates: Vec<Spanned<Predicate>>,

    /// The effect to apply when predicates match.
    pub effect: Spanned<Effect>,

    /// Source span for error reporting.
    pub span: Span,
}

impl Rule {
    /// Create a new rule.
    pub fn new(
        command: Spanned<CommandPattern>,
        predicates: Vec<Spanned<Predicate>>,
        effect: Spanned<Effect>,
        span: Span,
    ) -> Self {
        Self {
            command,
            predicates,
            effect,
            span,
        }
    }
}

/// Top-level configuration for the unified rule DSL.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Named predicate definitions.
    pub defines: Vec<Define>,

    /// Authorization rules.
    pub rules: Vec<Rule>,

    /// Security configuration.
    pub security: SecurityConfig,

    /// Validation checks.
    pub checks: Vec<Check>,
}

/// Security configuration.
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Environment variables that are safe to log.
    pub safe_env_vars: std::collections::HashSet<String>,
}

/// An embedded check for config validation.
#[derive(Debug, Clone)]
pub struct Check {
    /// The command to test.
    pub command: String,

    /// The expected decision.
    pub expected: Decision,

    /// Context facts for the test.
    pub context: crate::types::ContextFacts,

    /// Source span for error reporting.
    pub span: Span,
}

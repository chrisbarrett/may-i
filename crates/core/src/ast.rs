// Core AST types for the unified rule DSL.
// Redesigned for unified effect model where everything returns Decision | Nil.

use crate::doc::Doc;
use crate::pattern::{ArgPattern, CommandPattern};
use crate::primitives::{Decision, ToDoc};
use crate::span::Span;

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

    #[cfg(test)]
    pub(crate) fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Spanned<U> {
        Spanned {
            value: f(self.value),
            span: self.span,
        }
    }
}

/// Result of evaluating an effect: either a terminal decision or Nil (no match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectResult {
    /// Terminal decision reached with optional reason.
    Decision(Decision, Option<String>),
    /// No match - continue evaluating.
    Nil,
}

impl EffectResult {
    /// Check if this is Nil.
    pub fn is_nil(&self) -> bool {
        matches!(self, EffectResult::Nil)
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn is_decision(&self) -> bool {
        matches!(self, EffectResult::Decision(_, _))
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn decision(&self) -> Option<Decision> {
        match self {
            EffectResult::Decision(d, _) => Some(*d),
            EffectResult::Nil => None,
        }
    }

    #[cfg(any(test, feature = "test-generators"))]
    pub fn reason(&self) -> Option<&str> {
        match self {
            EffectResult::Decision(_, r) => r.as_deref(),
            EffectResult::Nil => None,
        }
    }
}

/// Unified Effect type where all forms evaluate to Decision | Nil.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Effect {
    // Terminal decisions
    /// A terminal decision (allow, ask, or deny) with optional reason.
    /// Syntax: `(effect :allow)`, `(effect :ask "reason")`, etc.
    Terminal {
        decision: Decision,
        reason: Option<String>,
    },

    // Pattern effects (return Allow on match, Nil otherwise)
    /// Command pattern match - returns Allow if command matches, Nil otherwise.
    /// Syntax: `"git"` or `(or "git" "gh")` in rule position
    CommandPattern(CommandPattern),

    /// Argument pattern match - returns Allow if args match, Nil otherwise.
    /// Syntax: `(positional ...)`, `(exact ...)`, `(anywhere ...)`, etc.
    ArgPattern(ArgPattern),

    // Effect combinators
    /// All effects must return non-Nil; returns first Nil or last effect's result.
    /// Syntax: `(and EFFECT ...)`
    And { effects: Vec<Spanned<Effect>> },

    /// Returns first non-Nil effect, or Nil if all return Nil.
    /// Syntax: `(or EFFECT ...)`
    Or { effects: Vec<Spanned<Effect>> },

    /// Inverts Allow/Nil, passes through Ask/Deny.
    /// Syntax: `(not EFFECT)`
    Not { effect: Box<Spanned<Effect>> },

    // Conditionals (predicates used for branching)
    /// Evaluate effect only if predicate matches.
    /// Syntax: `(when PREDICATE EFFECT)`
    When {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Evaluate effect only if predicate doesn't match.
    /// Syntax: `(unless PREDICATE EFFECT)`
    Unless {
        predicate: Spanned<Predicate>,
        effect: Box<Spanned<Effect>>,
    },

    /// Choose branch based on predicate.
    /// Syntax: `(if PREDICATE THEN-EFFECT ELSE-EFFECT)`
    If {
        predicate: Spanned<Predicate>,
        then_effect: Box<Spanned<Effect>>,
        else_effect: Box<Spanned<Effect>>,
    },

    /// First matching branch wins.
    /// Syntax: `(cond ((PREDICATE EFFECT) ...) [else EFFECT])`
    Cond {
        branches: Vec<(Spanned<Predicate>, Spanned<Effect>)>,
        fallback: Option<Box<Spanned<Effect>>>,
    },

    // Recursion
    /// Recursively evaluate inner command pattern.
    /// Returns inner decision if pattern matches, Nil otherwise.
    /// Syntax: `(may-i PATTERN)`
    MayI { pattern: ArgPattern },
}

impl Effect {
    #[cfg(test)]
    pub(crate) fn allow(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Allow,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn ask(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Ask,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn deny(reason: Option<String>) -> Self {
        Effect::Terminal {
            decision: Decision::Deny,
            reason,
        }
    }

    #[cfg(test)]
    pub(crate) fn command_pattern(pattern: CommandPattern) -> Self {
        Effect::CommandPattern(pattern)
    }

    #[cfg(test)]
    pub(crate) fn arg_pattern(pattern: ArgPattern) -> Self {
        Effect::ArgPattern(pattern)
    }

    #[cfg(test)]
    pub(crate) fn may_i(pattern: ArgPattern) -> Self {
        Effect::MayI { pattern }
    }

    /// Check if this is a terminal effect (Allow, Ask, or Deny).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Effect::Terminal { .. })
    }

    /// Check if this effect would match the given command name.
    /// Only meaningful for CommandPattern effects.
    pub fn matches_command(&self, command: &str) -> bool {
        match self {
            Effect::CommandPattern(pattern) => pattern.is_match(command),
            _ => false,
        }
    }

    #[cfg(test)]
    fn is_pattern(&self) -> bool {
        matches!(self, Effect::CommandPattern(_) | Effect::ArgPattern(_))
    }

    #[cfg(test)]
    fn is_combinator(&self) -> bool {
        matches!(
            self,
            Effect::And { .. } | Effect::Or { .. } | Effect::Not { .. }
        )
    }

    #[cfg(test)]
    fn is_conditional(&self) -> bool {
        matches!(
            self,
            Effect::When { .. } | Effect::Unless { .. } | Effect::If { .. } | Effect::Cond { .. }
        )
    }
}

impl std::fmt::Display for Effect {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Terminal {
                decision,
                reason: None,
            } => write!(f, "(effect {})", decision.keyword()),
            Effect::Terminal {
                decision,
                reason: Some(r),
            } => write!(f, "(effect {} \"{}\")", decision.keyword(), r),
            Effect::CommandPattern(_) => write!(f, "<command-pattern>"),
            Effect::ArgPattern(_) => write!(f, "<arg-pattern>"),
            Effect::And { .. } => write!(f, "<and-effect>"),
            Effect::Or { .. } => write!(f, "<or-effect>"),
            Effect::Not { .. } => write!(f, "<not-effect>"),
            Effect::When { .. } => write!(f, "<when-effect>"),
            Effect::Unless { .. } => write!(f, "<unless-effect>"),
            Effect::If { .. } => write!(f, "<if-effect>"),
            Effect::Cond { .. } => write!(f, "<cond-effect>"),
            Effect::MayI { .. } => write!(f, "<may-i-effect>"),
        }
    }
}

/// Predicate for use in conditional contexts (when/unless/if/cond).
/// Predicates evaluate to Match/NoMatch for branching decisions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Predicate {
    /// Fact query: checks if a fact exists or matches a pattern.
    /// Syntax: `(fact? FACT-QUERY)` (renamed from `has`)
    Fact(FactQuery),

    /// Argument pattern match as predicate: checks if arguments match.
    /// Returns Match if pattern matches, NoMatch otherwise.
    /// Syntax: `(positional ...)`, `(exact ...)`, `(anywhere ...)`, etc.
    Arg(ArgPattern),

    /// Reference to a named predicate defined with `(define NAME PREDICATE)`.
    /// Syntax: `NAME` (atom reference, resolved during validation)
    Named(String),

    /// All sub-predicates must match.
    /// Syntax: `(and PREDICATE ...)`
    And(Vec<Predicate>),

    /// Any sub-predicate must match.
    /// Syntax: `(or PREDICATE ...)`
    Or(Vec<Predicate>),

    /// Inverts a sub-predicate.
    /// Syntax: `(not PREDICATE)`
    Not(Box<Predicate>),
}

impl Predicate {
    /// Create a simple fact presence check.
    pub fn fact_presence(key: impl Into<String>) -> Self {
        Predicate::Fact(FactQuery::Presence {
            key: crate::Keyword::new(key).unwrap(),
        })
    }

    #[cfg(test)]
    fn fact_value(key: impl Into<String>, value: impl Into<String>) -> Self {
        use crate::predicates::FactPattern;
        Predicate::Fact(FactQuery::Value {
            key: crate::Keyword::new(key).unwrap(),
            pattern: FactPattern::Literal(value.into()),
        })
    }

    #[cfg(test)]
    pub(crate) fn arg(pattern: ArgPattern) -> Self {
        Predicate::Arg(pattern)
    }

    #[cfg(test)]
    pub(crate) fn and(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::And(predicates)
        }
    }

    #[cfg(test)]
    pub(crate) fn or(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::Or(predicates)
        }
    }

    #[cfg(test)]
    pub(crate) fn negate(predicate: Predicate) -> Self {
        Predicate::Not(Box::new(predicate))
    }
}

impl ToDoc for Predicate {
    fn to_doc(&self) -> Doc {
        match self {
            Predicate::Fact(query) => Doc::list(vec![Doc::atom("fact?"), query.to_doc()]),
            Predicate::Arg(_) => Doc::atom("<arg-predicate>"),
            Predicate::Named(name) => Doc::atom(name.clone()),
            Predicate::And(preds) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(preds.iter().map(|p| p.to_doc()));
                Doc::broken_list(cs)
            }
            Predicate::Or(preds) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(preds.iter().map(|p| p.to_doc()));
                Doc::broken_list(cs)
            }
            Predicate::Not(pred) => Doc::list(vec![Doc::atom("not"), pred.to_doc()]),
        }
    }
}

/// A predicate with source span tracking.
pub type SpannedPredicate = Spanned<Predicate>;

/// Fact query types (re-exported from predicates module).
pub use crate::predicates::FactQuery;

/// A named predicate definition.
/// Syntax: `(define NAME PREDICATE)`
#[derive(Debug, Clone)]
pub struct Define {
    /// The name of the predicate.
    pub name: String,

    /// The predicate body.
    pub predicate: SpannedPredicate,

    /// Source span for error reporting.
    pub span: Span,
}

impl Define {
    /// Create a new named predicate definition.
    pub fn new(name: impl Into<String>, predicate: SpannedPredicate, span: Span) -> Self {
        Self {
            name: name.into(),
            predicate,
            span,
        }
    }
}

/// An authorization rule.
/// Syntax: `(rule COMMAND EFFECT [CHECK...])`
///
/// A rule takes exactly two positional forms: a command pattern and a single
/// body effect. The body effect can be a terminal, a combinator, or a
/// conditional. Optional `(check ...)` forms may follow.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The command effect (position 1) - must return non-Nil for rule to apply.
    pub command_effect: Spanned<Effect>,

    /// The single body effect for this rule.
    pub effect: Spanned<Effect>,

    /// Validation checks associated with this rule.
    pub checks: Vec<Check>,

    /// Source span for error reporting.
    pub span: Span,
}

impl Rule {
    /// Create a new rule.
    pub fn new(
        command_effect: Spanned<Effect>,
        effect: Spanned<Effect>,
        checks: Vec<Check>,
        span: Span,
    ) -> Self {
        Self {
            command_effect,
            effect,
            checks,
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
    pub context: crate::context::ContextFacts,

    /// Source span for error reporting.
    pub span: Span,
}

impl ToDoc for Effect {
    fn to_doc(&self) -> Doc {
        match self {
            Effect::Terminal { decision, reason } => {
                let mut cs = vec![Doc::atom("effect"), Doc::atom(decision.keyword())];
                if let Some(r) = reason {
                    cs.push(Doc::atom(format!("\"{r}\"")));
                }
                Doc::list(cs)
            }
            Effect::CommandPattern(_) => Doc::atom("<command-pattern>"),
            Effect::ArgPattern(_) => Doc::atom("<arg-pattern>"),
            Effect::And { .. } => Doc::atom("<and-effect>"),
            Effect::Or { .. } => Doc::atom("<or-effect>"),
            Effect::Not { .. } => Doc::atom("<not-effect>"),
            Effect::When { .. } => Doc::atom("<when-effect>"),
            Effect::Unless { .. } => Doc::atom("<unless-effect>"),
            Effect::If { .. } => Doc::atom("<if-effect>"),
            Effect::Cond { .. } => Doc::atom("<cond-effect>"),
            Effect::MayI { .. } => Doc::atom("<may-i-effect>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{ArgPattern, CommandPattern, MatchMode};
    use crate::span::Span;

    #[test]
    fn spanned_new_creates_correctly() {
        let span = Span { start: 0, end: 5 };
        let spanned = Spanned::new("test", span);
        assert_eq!(spanned.value, "test");
        assert_eq!(spanned.span, span);
    }

    #[test]
    fn spanned_map_preserves_span() {
        let span = Span { start: 0, end: 5 };
        let spanned = Spanned::new(42, span);
        let mapped = spanned.map(|n| n.to_string());
        assert_eq!(mapped.value, "42");
        assert_eq!(mapped.span, span);
    }

    #[test]
    fn effect_result_is_nil_returns_correctly() {
        assert!(EffectResult::Nil.is_nil());
        assert!(!EffectResult::Decision(Decision::Allow, None).is_nil());
    }

    #[test]
    fn effect_result_is_decision_returns_correctly() {
        assert!(EffectResult::Decision(Decision::Allow, None).is_decision());
        assert!(!EffectResult::Nil.is_decision());
    }

    #[test]
    fn effect_result_decision_returns_some() {
        assert_eq!(
            EffectResult::Decision(Decision::Ask, None).decision(),
            Some(Decision::Ask)
        );
        assert_eq!(EffectResult::Nil.decision(), None);
    }

    #[test]
    fn effect_result_reason_returns_some_for_decision() {
        assert_eq!(
            EffectResult::Decision(Decision::Allow, Some("test".into())).reason(),
            Some("test")
        );
    }

    #[test]
    fn effect_result_reason_returns_none_for_nil() {
        assert_eq!(EffectResult::Nil.reason(), None);
    }

    #[test]
    fn effect_result_reason_returns_none_for_decision_without_reason() {
        assert_eq!(EffectResult::Decision(Decision::Deny, None).reason(), None);
    }

    #[test]
    fn effect_allow_creates_correctly() {
        let effect = Effect::allow(Some("reason".into()));
        assert!(
            matches!(effect, Effect::Terminal { decision: Decision::Allow, reason: Some(r) } if r == "reason")
        );
    }

    #[test]
    fn effect_ask_creates_correctly() {
        let effect = Effect::ask(None);
        assert!(matches!(
            effect,
            Effect::Terminal {
                decision: Decision::Ask,
                reason: None
            }
        ));
    }

    #[test]
    fn effect_deny_creates_correctly() {
        let effect = Effect::deny(Some("blocked".into()));
        assert!(
            matches!(effect, Effect::Terminal { decision: Decision::Deny, reason: Some(r) } if r == "blocked")
        );
    }

    #[test]
    fn effect_command_pattern_creates_correctly() {
        let pattern = CommandPattern::Literal("git".into());
        let effect = Effect::command_pattern(pattern);
        assert!(matches!(effect, Effect::CommandPattern(CommandPattern::Literal(s)) if s == "git"));
    }

    #[test]
    fn effect_arg_pattern_creates_correctly() {
        let pattern = ArgPattern::positional(vec![]);
        let effect = Effect::arg_pattern(pattern.clone());
        assert!(
            matches!(effect, Effect::ArgPattern(p) if matches!(p, ArgPattern::Ordered { mode: MatchMode::Positional, .. }))
        );
    }

    #[test]
    fn effect_may_i_creates_correctly() {
        let pattern = ArgPattern::positional(vec![]);
        let effect = Effect::may_i(pattern.clone());
        assert!(matches!(effect, Effect::MayI { .. }));
    }

    #[test]
    fn effect_is_terminal_returns_correctly() {
        assert!(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_terminal()
        );
        assert!(
            Effect::Terminal {
                decision: Decision::Ask,
                reason: None
            }
            .is_terminal()
        );
        assert!(
            Effect::Terminal {
                decision: Decision::Deny,
                reason: None
            }
            .is_terminal()
        );
        assert!(!Effect::CommandPattern(CommandPattern::Literal("git".into())).is_terminal());
        assert!(!Effect::ArgPattern(ArgPattern::positional(vec![])).is_terminal());
    }

    #[test]
    fn effect_is_pattern_returns_correctly() {
        assert!(Effect::CommandPattern(CommandPattern::Literal("git".into())).is_pattern());
        assert!(Effect::ArgPattern(ArgPattern::positional(vec![])).is_pattern());
        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_pattern()
        );
        assert!(!Effect::And { effects: vec![] }.is_pattern());
    }

    #[test]
    fn effect_is_combinator_returns_correctly() {
        let span = Span { start: 0, end: 1 };
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );

        assert!(Effect::And { effects: vec![] }.is_combinator());
        assert!(Effect::Or { effects: vec![] }.is_combinator());
        assert!(
            Effect::Not {
                effect: Box::new(effect.clone())
            }
            .is_combinator()
        );
        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_combinator()
        );
        assert!(!Effect::CommandPattern(CommandPattern::Literal("git".into())).is_combinator());
    }

    #[test]
    fn effect_is_conditional_returns_correctly() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );

        assert!(
            Effect::When {
                predicate: pred.clone(),
                effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::Unless {
                predicate: pred.clone(),
                effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::If {
                predicate: pred.clone(),
                then_effect: Box::new(effect.clone()),
                else_effect: Box::new(effect.clone()),
            }
            .is_conditional()
        );

        assert!(
            Effect::Cond {
                branches: vec![],
                fallback: None,
            }
            .is_conditional()
        );

        assert!(
            !Effect::Terminal {
                decision: Decision::Allow,
                reason: None
            }
            .is_conditional()
        );
    }

    #[test]
    fn predicate_fact_presence_creates_correctly() {
        let pred = Predicate::fact_presence(":via/ssh");
        assert!(matches!(
            pred,
            Predicate::Fact(FactQuery::Presence { key })
            if key == ":via/ssh"
        ));
    }

    #[test]
    fn predicate_fact_value_creates_correctly() {
        use crate::predicates::FactPattern;
        let pred = Predicate::fact_value(":opencode/agent", "build");
        assert!(matches!(
            pred,
            Predicate::Fact(FactQuery::Value { key, pattern: FactPattern::Literal(val) })
            if key == ":opencode/agent" && val == "build"
        ));
    }

    #[test]
    fn predicate_arg_creates_correctly() {
        let pattern = ArgPattern::positional(vec![]);
        let pred = Predicate::arg(pattern);
        assert!(matches!(
            pred,
            Predicate::Arg(ArgPattern::Ordered {
                mode: MatchMode::Positional,
                ..
            })
        ));
    }

    #[test]
    fn predicate_and_with_single_returns_unwrapped() {
        let pred = Predicate::fact_presence(":test");
        let result = Predicate::and(vec![pred]);
        assert!(matches!(result, Predicate::Fact(_)));
    }

    #[test]
    fn predicate_and_with_multiple_creates_and() {
        let preds = vec![
            Predicate::fact_presence(":a"),
            Predicate::fact_presence(":b"),
        ];
        let result = Predicate::and(preds);
        assert!(matches!(result, Predicate::And(children) if children.len() == 2));
    }

    #[test]
    fn predicate_or_with_single_returns_unwrapped() {
        let pred = Predicate::fact_presence(":test");
        let result = Predicate::or(vec![pred]);
        assert!(matches!(result, Predicate::Fact(_)));
    }

    #[test]
    fn predicate_or_with_multiple_creates_or() {
        let preds = vec![
            Predicate::fact_presence(":a"),
            Predicate::fact_presence(":b"),
        ];
        let result = Predicate::or(preds);
        assert!(matches!(result, Predicate::Or(children) if children.len() == 2));
    }

    #[test]
    fn predicate_negate_creates_not() {
        let inner = Predicate::fact_presence(":test");
        let result = Predicate::negate(inner);
        assert!(
            matches!(result, Predicate::Not(boxed) if matches!(boxed.as_ref(), Predicate::Fact(_)))
        );
    }

    #[test]
    fn define_new_creates_correctly() {
        let span = Span { start: 0, end: 10 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let define = Define::new("my-pred", pred, span);

        assert_eq!(define.name, "my-pred");
        assert_eq!(define.span, span);
    }

    #[test]
    fn rule_new_creates_correctly() {
        let span = Span { start: 0, end: 20 };
        let cmd_effect = Spanned::new(
            Effect::command_pattern(CommandPattern::Literal("git".into())),
            span,
        );
        let effect = Spanned::new(Effect::ask(None), span);
        let rule = Rule::new(cmd_effect, effect, vec![], span);

        assert!(
            matches!(rule.command_effect.value, Effect::CommandPattern(CommandPattern::Literal(s)) if s == "git")
        );
        assert_eq!(rule.span, span);
    }

    #[test]
    fn security_config_default_is_empty() {
        let config = SecurityConfig::default();
        assert!(config.safe_env_vars.is_empty());
    }

    #[test]
    fn config_default_is_empty() {
        let config = Config::default();
        assert!(config.defines.is_empty());
        assert!(config.rules.is_empty());
        assert!(config.checks.is_empty());
        assert!(config.security.safe_env_vars.is_empty());
    }

    #[test]
    fn effect_to_doc_allow_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Allow,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :allow)");
    }

    #[test]
    fn effect_to_doc_allow_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Allow,
            reason: Some("safe command".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :allow \"safe command\")");
    }

    #[test]
    fn effect_to_doc_ask_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Ask,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :ask)");
    }

    #[test]
    fn effect_to_doc_ask_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Ask,
            reason: Some("confirm".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :ask \"confirm\")");
    }

    #[test]
    fn effect_to_doc_deny_without_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Deny,
            reason: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :deny)");
    }

    #[test]
    fn effect_to_doc_deny_with_reason() {
        let doc = Effect::Terminal {
            decision: Decision::Deny,
            reason: Some("blocked".into()),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "(effect :deny \"blocked\")");
    }

    #[test]
    fn effect_to_doc_command_pattern_placeholder() {
        let doc = Effect::CommandPattern(CommandPattern::Literal("git".into())).to_doc();
        assert_eq!(doc_text(&doc), "<command-pattern>");
    }

    #[test]
    fn effect_to_doc_arg_pattern_placeholder() {
        let doc = Effect::ArgPattern(ArgPattern::positional(vec![])).to_doc();
        assert_eq!(doc_text(&doc), "<arg-pattern>");
    }

    #[test]
    fn effect_to_doc_and_placeholder() {
        let doc = Effect::And { effects: vec![] }.to_doc();
        assert_eq!(doc_text(&doc), "<and-effect>");
    }

    #[test]
    fn effect_to_doc_or_placeholder() {
        let doc = Effect::Or { effects: vec![] }.to_doc();
        assert_eq!(doc_text(&doc), "<or-effect>");
    }

    #[test]
    fn effect_to_doc_not_placeholder() {
        let span = Span { start: 0, end: 1 };
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::Not {
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<not-effect>");
    }

    #[test]
    fn effect_to_doc_when_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::When {
            predicate: pred,
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<when-effect>");
    }

    #[test]
    fn effect_to_doc_unless_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::Unless {
            predicate: pred,
            effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<unless-effect>");
    }

    #[test]
    fn effect_to_doc_if_placeholder() {
        let span = Span { start: 0, end: 1 };
        let pred = Spanned::new(Predicate::fact_presence(":test"), span);
        let effect = Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            },
            span,
        );
        let doc = Effect::If {
            predicate: pred,
            then_effect: Box::new(effect.clone()),
            else_effect: Box::new(effect),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<if-effect>");
    }

    #[test]
    fn effect_to_doc_cond_placeholder() {
        let doc = Effect::Cond {
            branches: vec![],
            fallback: None,
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<cond-effect>");
    }

    #[test]
    fn effect_to_doc_may_i_placeholder() {
        let doc = Effect::MayI {
            pattern: ArgPattern::positional(vec![]),
        }
        .to_doc();
        assert_eq!(doc_text(&doc), "<may-i-effect>");
    }

    fn doc_text(doc: &crate::doc::Doc) -> String {
        doc.fold(&|node, _ann| match node {
            crate::doc::DocF::Atom(s) => s.clone(),
            crate::doc::DocF::List(cs) => format!("({})", cs.join(" ")),
            crate::doc::DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
        })
    }
}

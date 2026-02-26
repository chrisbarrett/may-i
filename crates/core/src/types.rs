// Shared domain types for authorization rules and configuration.

use may_i_sexpr::Span;

/// The three possible authorization decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl Decision {
    /// Returns the more restrictive of two decisions.
    pub fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Decision::Deny, _) | (_, Decision::Deny) => Decision::Deny,
            (Decision::Ask, _) | (_, Decision::Ask) => Decision::Ask,
            _ => Decision::Allow,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Ask => write!(f, "ask"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}

/// An authorization effect: a decision with an optional reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub decision: Decision,
    pub reason: Option<String>,
}

/// An expression that matches a single string, optionally carrying effects.
#[derive(Clone)]
pub enum Expr {
    /// Exact string match.
    Literal(String),
    /// Regex match.
    Regex(regex::Regex),
    /// Matches any string.
    Wildcard,
    /// All sub-expressions must match.
    And(Vec<Expr>),
    /// Any sub-expression must match.
    Or(Vec<Expr>),
    /// Inverts the match result.
    Not(Box<Expr>),
    /// Branches with effects; first matching branch wins.
    Cond(Vec<ExprBranch>),
}

impl Expr {
    /// Find the effect from the first matching Cond branch for the given text.
    pub fn find_effect(&self, text: &str) -> Option<&Effect> {
        match self {
            Expr::Cond(branches) => branches
                .iter()
                .find(|b| b.test.is_match(text))
                .map(|b| &b.effect),
            Expr::And(exprs) | Expr::Or(exprs) => {
                exprs.iter().find_map(|e| e.find_effect(text))
            }
            Expr::Not(expr) => expr.find_effect(text),
            Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => None,
        }
    }

    /// Check if the expression matches the given text (ignoring effects).
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Expr::Literal(s) => text == s,
            Expr::Regex(re) => re.is_match(text),
            Expr::Wildcard => true,
            Expr::And(exprs) => exprs.iter().all(|e| e.is_match(text)),
            Expr::Or(exprs) => exprs.iter().any(|e| e.is_match(text)),
            Expr::Not(expr) => !expr.is_match(text),
            Expr::Cond(branches) => branches.iter().any(|b| b.test.is_match(text)),
        }
    }

    /// Returns true if this is the wildcard expression.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Expr::Wildcard)
    }
}

impl std::fmt::Debug for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(s) => f.debug_tuple("Literal").field(s).finish(),
            Expr::Regex(re) => f.debug_tuple("Regex").field(&re.as_str()).finish(),
            Expr::Wildcard => write!(f, "Wildcard"),
            Expr::And(exprs) => f.debug_tuple("And").field(exprs).finish(),
            Expr::Or(exprs) => f.debug_tuple("Or").field(exprs).finish(),
            Expr::Not(expr) => f.debug_tuple("Not").field(expr).finish(),
            Expr::Cond(branches) => f.debug_tuple("Cond").field(branches).finish(),
        }
    }
}

/// A branch in an expression-level cond.
#[derive(Debug, Clone)]
pub struct ExprBranch {
    pub test: Expr,
    pub effect: Effect,
}

/// Source file information for diagnostics.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub filename: String,
    pub content: String,
}

/// Top-level configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wrappers: Vec<Wrapper>,
    pub security: SecurityConfig,
    pub source_info: Option<SourceInfo>,
}

/// Security section of config.
#[derive(Clone, Debug, Default)]
pub struct SecurityConfig {
    pub safe_env_vars: std::collections::HashSet<String>,
}

/// A configured authorization rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub command: CommandMatcher,
    pub matcher: Option<ArgMatcher>,
    pub effect: Option<Effect>,
    pub checks: Vec<Check>,
    pub source_span: Span,
}

/// A single branch inside a matcher-level `cond` form.
#[derive(Debug, Clone)]
pub struct CondBranch {
    /// None means catch-all (`else`).
    pub matcher: Option<ArgMatcher>,
    pub effect: Effect,
}

/// A positional expression with optional quantifier.
#[derive(Clone)]
pub enum PosExpr {
    /// Match exactly one arg.
    One(Expr),
    /// Match zero or one arg: `(? e)`
    Optional(Expr),
    /// Match one or more args: `(+ e)`
    OneOrMore(Expr),
    /// Match zero or more args: `(* e)`
    ZeroOrMore(Expr),
}

impl PosExpr {
    /// Access the inner expression.
    pub fn expr(&self) -> &Expr {
        match self {
            PosExpr::One(e) | PosExpr::Optional(e) | PosExpr::OneOrMore(e) | PosExpr::ZeroOrMore(e) => e,
        }
    }

    /// Delegate to the inner expression's `is_match`.
    pub fn is_match(&self, text: &str) -> bool {
        self.expr().is_match(text)
    }

    /// Delegate to the inner expression's `is_wildcard`.
    pub fn is_wildcard(&self) -> bool {
        self.expr().is_wildcard()
    }
}

impl std::fmt::Debug for PosExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PosExpr::One(e) => write!(f, "{:?}", e),
            PosExpr::Optional(e) => f.debug_tuple("Optional").field(e).finish(),
            PosExpr::OneOrMore(e) => f.debug_tuple("OneOrMore").field(e).finish(),
            PosExpr::ZeroOrMore(e) => f.debug_tuple("ZeroOrMore").field(e).finish(),
        }
    }
}

/// Argument matching strategies.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    /// Match positional args by position (skip flags). Wildcard = any value.
    Positional(Vec<PosExpr>),
    /// Like `Positional`, but requires exactly as many positional args as patterns.
    ExactPositional(Vec<PosExpr>),
    /// Token appears anywhere in argv.
    Anywhere(Vec<Expr>),
    /// All sub-matchers must match.
    And(Vec<ArgMatcher>),
    /// Any sub-matcher must match.
    Or(Vec<ArgMatcher>),
    /// Inverts a sub-matcher.
    Not(Box<ArgMatcher>),
    /// Branch on args; first matching branch wins.
    Cond(Vec<CondBranch>),
}

impl ArgMatcher {
    /// True if any expression in this matcher tree contains a Cond with effects.
    pub fn has_effect(&self) -> bool {
        match self {
            ArgMatcher::Positional(pexprs) | ArgMatcher::ExactPositional(pexprs) => {
                pexprs.iter().any(|pe| has_expr_effect(pe.expr()))
            }
            ArgMatcher::Anywhere(exprs) => exprs.iter().any(has_expr_effect),
            ArgMatcher::And(matchers) | ArgMatcher::Or(matchers) => {
                matchers.iter().any(|m| m.has_effect())
            }
            ArgMatcher::Not(inner) => inner.has_effect(),
            ArgMatcher::Cond(branches) => branches.iter().any(|b| {
                b.matcher.as_ref().is_some_and(|m| m.has_effect())
            }),
        }
    }
}

/// True if this expression (or any sub-expression) is a Cond with effects.
fn has_expr_effect(expr: &Expr) -> bool {
    match expr {
        Expr::Cond(_) => true,
        Expr::And(exprs) | Expr::Or(exprs) => exprs.iter().any(has_expr_effect),
        Expr::Not(e) => has_expr_effect(e),
        Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => false,
    }
}

/// Wrapper configuration for command unwrapping.
#[derive(Debug, Clone)]
pub struct Wrapper {
    pub command: String,
    pub steps: Vec<WrapperStep>,
}

/// A single step in a wrapper definition.
#[derive(Debug, Clone)]
pub enum WrapperStep {
    /// Validate positional (non-flag) args match patterns in order.
    /// If `capture` is `Some`, the inner command starts immediately after
    /// the last matched positional in the original arg list.
    Positional {
        patterns: Vec<Expr>,
        capture: Option<CaptureKind>,
    },
    /// Find a named flag or delimiter; the inner command starts after it.
    Flag { name: String, capture: CaptureKind },
}

/// Which part of the remaining args becomes the inner command.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureKind {
    /// Everything remaining is the command followed by its arguments.
    CommandArgs,
    /// The first remaining token is the command (no arguments).
    Command,
    /// All remaining tokens are arguments to an implicit command.
    Args,
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
    pub trace: Vec<String>,
}

impl EvalResult {
    pub fn new(decision: Decision, reason: Option<String>) -> Self {
        Self {
            decision,
            reason,
            trace: vec![],
        }
    }
}

#[derive(Clone)]
pub enum CommandMatcher {
    Exact(String),
    Regex(regex::Regex),
    List(Vec<String>),
}

impl std::fmt::Debug for CommandMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandMatcher::Exact(s) => f.debug_tuple("Exact").field(s).finish(),
            CommandMatcher::Regex(re) => f.debug_tuple("Regex").field(&re.as_str()).finish(),
            CommandMatcher::List(v) => f.debug_tuple("List").field(v).finish(),
        }
    }
}

/// An embedded check for config validation.
#[derive(Debug, Clone)]
pub struct Check {
    pub command: String,
    pub expected: Decision,
    pub source_span: Span,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Decision::most_restrictive ---

    #[test]
    fn most_restrictive_allow_allow() {
        assert_eq!(Decision::Allow.most_restrictive(Decision::Allow), Decision::Allow);
    }

    #[test]
    fn most_restrictive_allow_ask() {
        assert_eq!(Decision::Allow.most_restrictive(Decision::Ask), Decision::Ask);
    }

    #[test]
    fn most_restrictive_allow_deny() {
        assert_eq!(Decision::Allow.most_restrictive(Decision::Deny), Decision::Deny);
    }

    #[test]
    fn most_restrictive_ask_allow() {
        assert_eq!(Decision::Ask.most_restrictive(Decision::Allow), Decision::Ask);
    }

    #[test]
    fn most_restrictive_ask_ask() {
        assert_eq!(Decision::Ask.most_restrictive(Decision::Ask), Decision::Ask);
    }

    #[test]
    fn most_restrictive_ask_deny() {
        assert_eq!(Decision::Ask.most_restrictive(Decision::Deny), Decision::Deny);
    }

    #[test]
    fn most_restrictive_deny_allow() {
        assert_eq!(Decision::Deny.most_restrictive(Decision::Allow), Decision::Deny);
    }

    #[test]
    fn most_restrictive_deny_ask() {
        assert_eq!(Decision::Deny.most_restrictive(Decision::Ask), Decision::Deny);
    }

    #[test]
    fn most_restrictive_deny_deny() {
        assert_eq!(Decision::Deny.most_restrictive(Decision::Deny), Decision::Deny);
    }

    // --- Decision::Display ---

    #[test]
    fn decision_display_allow() {
        assert_eq!(format!("{}", Decision::Allow), "allow");
    }

    #[test]
    fn decision_display_ask() {
        assert_eq!(format!("{}", Decision::Ask), "ask");
    }

    #[test]
    fn decision_display_deny() {
        assert_eq!(format!("{}", Decision::Deny), "deny");
    }

    // --- Expr::is_match ---

    #[test]
    fn expr_literal_exact_match() {
        let e = Expr::Literal("hello".into());
        assert!(e.is_match("hello"));
    }

    #[test]
    fn expr_literal_no_match() {
        let e = Expr::Literal("hello".into());
        assert!(!e.is_match("world"));
    }

    #[test]
    fn expr_literal_no_partial_match() {
        let e = Expr::Literal("hello".into());
        assert!(!e.is_match("hello world"));
    }

    #[test]
    fn expr_regex_match() {
        let e = Expr::Regex(regex::Regex::new("^foo.*bar$").unwrap());
        assert!(e.is_match("fooXbar"));
    }

    #[test]
    fn expr_regex_no_match() {
        let e = Expr::Regex(regex::Regex::new("^foo.*bar$").unwrap());
        assert!(!e.is_match("baz"));
    }

    #[test]
    fn expr_wildcard_matches_anything() {
        assert!(Expr::Wildcard.is_match("anything"));
        assert!(Expr::Wildcard.is_match(""));
    }

    #[test]
    fn expr_and_all_match() {
        let e = Expr::And(vec![
            Expr::Regex(regex::Regex::new("^f").unwrap()),
            Expr::Regex(regex::Regex::new("o$").unwrap()),
        ]);
        assert!(e.is_match("foo"));
    }

    #[test]
    fn expr_and_one_fails() {
        let e = Expr::And(vec![
            Expr::Regex(regex::Regex::new("^f").unwrap()),
            Expr::Regex(regex::Regex::new("z$").unwrap()),
        ]);
        assert!(!e.is_match("foo"));
    }

    #[test]
    fn expr_or_any_match() {
        let e = Expr::Or(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
        ]);
        assert!(e.is_match("a"));
        assert!(e.is_match("b"));
        assert!(!e.is_match("c"));
    }

    #[test]
    fn expr_not_inverts() {
        let e = Expr::Not(Box::new(Expr::Literal("bad".into())));
        assert!(e.is_match("good"));
        assert!(!e.is_match("bad"));
    }

    #[test]
    fn expr_cond_matches_branch() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("a".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        assert!(e.is_match("a"));
        assert!(!e.is_match("b"));
    }

    // --- Expr::is_wildcard ---

    #[test]
    fn expr_is_wildcard() {
        assert!(Expr::Wildcard.is_wildcard());
    }

    #[test]
    fn expr_literal_not_wildcard() {
        assert!(!Expr::Literal("hello".into()).is_wildcard());
    }

    #[test]
    fn expr_regex_not_wildcard() {
        assert!(!Expr::Regex(regex::Regex::new("^.*$").unwrap()).is_wildcard());
    }

    // --- Expr::Debug ---

    #[test]
    fn expr_debug_literal() {
        let e = Expr::Literal("hello".into());
        assert_eq!(format!("{:?}", e), r#"Literal("hello")"#);
    }

    #[test]
    fn expr_debug_regex() {
        let e = Expr::Regex(regex::Regex::new("^foo$").unwrap());
        assert_eq!(format!("{:?}", e), r#"Regex("^foo$")"#);
    }

    #[test]
    fn expr_debug_wildcard() {
        assert_eq!(format!("{:?}", Expr::Wildcard), "Wildcard");
    }

    // --- CommandMatcher::Debug ---

    #[test]
    fn command_matcher_debug_exact() {
        let m = CommandMatcher::Exact("git".to_string());
        assert_eq!(format!("{:?}", m), r#"Exact("git")"#);
    }

    #[test]
    fn command_matcher_debug_regex() {
        let m = CommandMatcher::Regex(regex::Regex::new("^git.*$").unwrap());
        assert_eq!(format!("{:?}", m), r#"Regex("^git.*$")"#);
    }

    #[test]
    fn command_matcher_debug_list() {
        let m = CommandMatcher::List(vec!["a".into(), "b".into()]);
        assert_eq!(format!("{:?}", m), r#"List(["a", "b"])"#);
    }

    // --- SecurityConfig::default ---

    #[test]
    fn security_config_default_is_empty() {
        let sc = SecurityConfig::default();
        assert!(sc.safe_env_vars.is_empty());
    }

    // --- SecurityConfig::Debug ---

    #[test]
    fn security_config_debug() {
        let sc = SecurityConfig::default();
        let dbg = format!("{:?}", sc);
        assert!(dbg.contains("SecurityConfig"));
    }

    // --- Expr::Debug (And, Or, Not, Cond) ---

    #[test]
    fn expr_debug_and() {
        let e = Expr::And(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("And("));
    }

    #[test]
    fn expr_debug_or() {
        let e = Expr::Or(vec![Expr::Literal("a".into())]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Or("));
    }

    #[test]
    fn expr_debug_not() {
        let e = Expr::Not(Box::new(Expr::Wildcard));
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Not("));
    }

    #[test]
    fn expr_debug_cond() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Cond("));
    }

    // --- PosExpr::Debug ---

    #[test]
    fn pos_expr_debug_one() {
        let pe = PosExpr::One(Expr::Literal("x".into()));
        assert_eq!(format!("{:?}", pe), r#"Literal("x")"#);
    }

    #[test]
    fn pos_expr_debug_optional() {
        let pe = PosExpr::Optional(Expr::Wildcard);
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("Optional("));
    }

    #[test]
    fn pos_expr_debug_one_or_more() {
        let pe = PosExpr::OneOrMore(Expr::Wildcard);
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("OneOrMore("));
    }

    #[test]
    fn pos_expr_debug_zero_or_more() {
        let pe = PosExpr::ZeroOrMore(Expr::Wildcard);
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("ZeroOrMore("));
    }

    // --- PosExpr delegation ---

    #[test]
    fn pos_expr_is_match_delegates() {
        let pe = PosExpr::Optional(Expr::Literal("x".into()));
        assert!(pe.is_match("x"));
        assert!(!pe.is_match("y"));
    }

    #[test]
    fn pos_expr_is_wildcard_delegates() {
        assert!(PosExpr::ZeroOrMore(Expr::Wildcard).is_wildcard());
        assert!(!PosExpr::One(Expr::Literal("x".into())).is_wildcard());
    }

    // --- has_effect for PosExpr paths ---

    #[test]
    fn has_effect_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]);
        assert!(m.has_effect());
    }

    #[test]
    fn has_effect_exact_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::ExactPositional(vec![PosExpr::Optional(cond_expr)]);
        assert!(m.has_effect());
    }

    #[test]
    fn has_effect_positional_no_cond() {
        let m = ArgMatcher::Positional(vec![PosExpr::One(Expr::Wildcard)]);
        assert!(!m.has_effect());
    }

    // --- Expr::find_effect for And/Or/Not ---

    #[test]
    fn find_effect_through_and() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let e = Expr::And(vec![cond]);
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Allow);
        assert!(e.find_effect("y").is_none());
    }

    #[test]
    fn find_effect_through_or() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let e = Expr::Or(vec![Expr::Literal("z".into()), cond]);
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Deny);
    }

    #[test]
    fn find_effect_through_not() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect { decision: Decision::Ask, reason: None },
        }]);
        let e = Expr::Not(Box::new(cond));
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Ask);
    }
}

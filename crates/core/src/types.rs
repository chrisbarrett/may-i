// Shared domain types for authorization rules and configuration.

use crate::doc::Doc;
use crate::span::{Span, offset_to_line_col};

/// The three possible authorization decisions.
/// Ordered from least to most restrictive: Allow < Ask < Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl Decision {
    /// Returns the more restrictive of two decisions.
    pub fn most_restrictive(self, other: Self) -> Self {
        self.max(other)
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

impl Effect {
    pub fn to_doc(&self) -> Doc {
        let mut cs = vec![Doc::atom("effect"), Doc::atom(format!(":{}", self.decision))];
        if let Some(r) = &self.reason {
            cs.push(Doc::atom(format!("\"{r}\"")));
        }
        Doc::list(cs)
    }
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(r) => write!(f, "(effect :{} \"{}\")", self.decision, r),
            None => write!(f, "(effect :{})", self.decision),
        }
    }
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

    pub fn to_doc(&self) -> Doc {
        match self {
            Expr::Literal(s) => Doc::atom(format!("\"{s}\"")),
            Expr::Regex(re) => Doc::list(vec![
                Doc::atom("regex"),
                Doc::atom(format!("\"{}\"", re.as_str())),
            ]),
            Expr::Wildcard => Doc::atom("*"),
            Expr::And(exprs) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                if exprs.len() > 4 { Doc::broken_list(cs) } else { Doc::list(cs) }
            }
            Expr::Or(exprs) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                if exprs.len() > 4 { Doc::broken_list(cs) } else { Doc::list(cs) }
            }
            Expr::Not(inner) => Doc::list(vec![Doc::atom("not"), inner.to_doc()]),
            Expr::Cond(branches) => {
                let mut cs = vec![Doc::atom("cond")];
                for b in branches {
                    cs.push(Doc::list(vec![b.test.to_doc(), b.effect.to_doc()]));
                }
                Doc::list(cs)
            }
        }
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(s) => write!(f, "\"{s}\""),
            Expr::Regex(re) => write!(f, "(regex \"{}\")", re.as_str()),
            Expr::Wildcard => write!(f, "*"),
            Expr::And(exprs) => {
                write!(f, "(and")?;
                for e in exprs {
                    write!(f, " {e}")?;
                }
                write!(f, ")")
            }
            Expr::Or(exprs) => {
                write!(f, "(or")?;
                for e in exprs {
                    write!(f, " {e}")?;
                }
                write!(f, ")")
            }
            Expr::Not(inner) => write!(f, "(not {inner})"),
            Expr::Cond(branches) => {
                write!(f, "(cond")?;
                for b in branches {
                    write!(f, " ({} {})", b.test, b.effect)?;
                }
                write!(f, ")")
            }
        }
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

impl SourceInfo {
    /// Format a source location as `file:line:col` from a span.
    pub fn location_of(&self, span: Span) -> String {
        let (line, col) = offset_to_line_col(&self.content, span.start);
        format!("{}:{}:{}", self.filename, line, col)
    }

    /// Return the 1-based line number for a span.
    pub fn line_of(&self, span: Span) -> usize {
        offset_to_line_col(&self.content, span.start).0
    }
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
    pub body: RuleBody,
    pub checks: Vec<Check>,
    pub source_span: Span,
}

/// What a rule does when the command name matches.
#[derive(Debug, Clone)]
pub enum RuleBody {
    /// Apply a fixed effect, optionally requiring an arg matcher to succeed first.
    Effect { matcher: Option<ArgMatcher>, effect: Effect },
    /// The matcher tree itself determines the effect (via embedded Cond branches).
    Branching(ArgMatcher),
}

impl RuleBody {
    pub fn to_doc(&self) -> Vec<Doc> {
        match self {
            RuleBody::Effect { matcher: None, effect } => {
                vec![effect.to_doc()]
            }
            RuleBody::Effect { matcher: Some(m), effect } => {
                vec![
                    Doc::list(vec![Doc::atom("args"), m.to_doc()]),
                    effect.to_doc(),
                ]
            }
            RuleBody::Branching(m) => {
                vec![Doc::list(vec![Doc::atom("args"), m.to_doc()])]
            }
        }
    }
}

impl Rule {
    pub fn to_doc(&self) -> Doc {
        let mut cs = vec![Doc::atom("rule"), self.command.to_doc()];
        cs.extend(self.body.to_doc());
        Doc::list(cs)
    }
}

/// A single guarded branch inside a matcher-level `cond` form.
#[derive(Debug, Clone)]
pub struct CondBranch {
    pub matcher: ArgMatcher,
    pub effect: Effect,
}

/// The branches and optional fallback of a matcher-level `cond`.
#[derive(Debug, Clone)]
pub struct CondArm {
    pub branches: Vec<CondBranch>,
    pub fallback: Option<Effect>,
}

impl CondArm {
    pub fn to_doc(&self) -> Doc {
        let mut cs = vec![Doc::atom("cond")];
        for b in &self.branches {
            cs.push(Doc::list(vec![b.matcher.to_doc(), b.effect.to_doc()]));
        }
        if let Some(fb) = &self.fallback {
            cs.push(Doc::list(vec![Doc::atom("else"), fb.to_doc()]));
        }
        Doc::list(cs)
    }
}

/// How many arguments a positional expression consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    /// Match exactly one arg.
    One,
    /// Match zero or one arg: `(? e)`
    Optional,
    /// Match one or more args: `(+ e)`
    OneOrMore,
    /// Match zero or more args: `(* e)`
    ZeroOrMore,
}

impl Quantifier {
    /// Minimum number of args this quantifier requires.
    pub fn min(self) -> usize {
        match self {
            Quantifier::One | Quantifier::OneOrMore => 1,
            Quantifier::Optional | Quantifier::ZeroOrMore => 0,
        }
    }

    /// Whether this quantifier consumes multiple args.
    pub fn is_repeating(self) -> bool {
        matches!(self, Quantifier::OneOrMore | Quantifier::ZeroOrMore)
    }
}

/// A positional expression with a quantifier.
#[derive(Clone)]
pub struct PosExpr {
    pub quantifier: Quantifier,
    pub expr: Expr,
}

impl PosExpr {
    /// Shorthand: match exactly one arg.
    pub fn one(expr: Expr) -> Self {
        Self { quantifier: Quantifier::One, expr }
    }

    /// Delegate to the inner expression's `is_match`.
    pub fn is_match(&self, text: &str) -> bool {
        self.expr.is_match(text)
    }

    /// Delegate to the inner expression's `is_wildcard`.
    pub fn is_wildcard(&self) -> bool {
        self.expr.is_wildcard()
    }

    pub fn to_doc(&self) -> Doc {
        match self.quantifier {
            Quantifier::One => self.expr.to_doc(),
            Quantifier::Optional => Doc::list(vec![Doc::atom("?"), self.expr.to_doc()]),
            Quantifier::OneOrMore => Doc::list(vec![Doc::atom("+"), self.expr.to_doc()]),
            Quantifier::ZeroOrMore => Doc::list(vec![Doc::atom("*"), self.expr.to_doc()]),
        }
    }
}

impl std::fmt::Debug for PosExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.quantifier {
            Quantifier::One => write!(f, "{:?}", self.expr),
            Quantifier::Optional => f.debug_tuple("Optional").field(&self.expr).finish(),
            Quantifier::OneOrMore => f.debug_tuple("OneOrMore").field(&self.expr).finish(),
            Quantifier::ZeroOrMore => f.debug_tuple("ZeroOrMore").field(&self.expr).finish(),
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
    /// Branch on args; first matching branch wins, with optional else fallback.
    Cond(CondArm),
}

impl ArgMatcher {
    pub fn to_doc(&self) -> Doc {
        match self {
            ArgMatcher::Positional(pexprs) => {
                let mut cs = vec![Doc::atom("positional")];
                cs.extend(pexprs.iter().map(|pe| pe.to_doc()));
                Doc::list(cs)
            }
            ArgMatcher::ExactPositional(pexprs) => {
                let mut cs = vec![Doc::atom("exact")];
                cs.extend(pexprs.iter().map(|pe| pe.to_doc()));
                Doc::list(cs)
            }
            ArgMatcher::Anywhere(exprs) => {
                let mut cs = vec![Doc::atom("anywhere")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                Doc::list(cs)
            }
            ArgMatcher::And(matchers) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(matchers.iter().map(|m| m.to_doc()));
                Doc::list(cs)
            }
            ArgMatcher::Or(matchers) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(matchers.iter().map(|m| m.to_doc()));
                Doc::list(cs)
            }
            ArgMatcher::Not(inner) => Doc::list(vec![Doc::atom("not"), inner.to_doc()]),
            ArgMatcher::Cond(arm) => arm.to_doc(),
        }
    }

    /// True if any expression in this matcher tree contains a Cond with effects.
    pub fn has_effect(&self) -> bool {
        match self {
            ArgMatcher::Positional(pexprs) | ArgMatcher::ExactPositional(pexprs) => {
                pexprs.iter().any(|pe| has_expr_effect(&pe.expr))
            }
            ArgMatcher::Anywhere(exprs) => exprs.iter().any(has_expr_effect),
            ArgMatcher::And(matchers) | ArgMatcher::Or(matchers) => {
                matchers.iter().any(|m| m.has_effect())
            }
            ArgMatcher::Not(inner) => inner.has_effect(),
            ArgMatcher::Cond(arm) => arm.branches.iter().any(|b| b.matcher.has_effect()),
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
    /// If `capture` is true, the inner command starts immediately after
    /// the last matched positional in the original arg list.
    Positional {
        patterns: Vec<Expr>,
        capture: bool,
    },
    /// Find a named flag or delimiter; the inner command starts after it.
    Flag { name: String },
}

/// Annotation placed on Doc nodes during rule evaluation.
///
/// Each node in a `Doc<Option<EvalAnn>>` carries `Some(ann)` if the evaluator
/// visited it, or `None` if it was structural scaffolding.
#[derive(Debug, Clone)]
pub enum EvalAnn {
    /// Command name matched or didn't.
    CommandMatch(bool),
    /// Expression was tested against a resolved argument.
    ExprVsArg { arg: String, matched: bool },
    /// Quantified pattern consumed some arguments.
    Quantifier { count: usize, matched: bool },
    /// Required positional argument was missing.
    Missing,
    /// Token-anywhere search against all args.
    Anywhere { args: Vec<String>, matched: bool },
    /// A conditional branch was selected (expr-level or matcher-level).
    CondBranch { decision: Decision },
    /// A conditional else/fallback was selected.
    CondElse { decision: Decision },
    /// Exact positional vector equality: patterns vs actual args.
    ExactArgs { patterns: Vec<String>, args: Vec<String>, matched: bool },
    /// Exact positional had leftover arguments.
    ExactRemainder { count: usize },
    /// Overall args match result.
    ArgsResult(bool),
    /// The effect produced by this rule.
    RuleEffect { decision: Decision, reason: Option<String> },
    /// No rule matched; defaulting to ask.
    DefaultAsk,
}

/// A single entry in an evaluation trace.
#[derive(Debug, Clone)]
pub enum TraceEntry {
    /// An annotated rule evaluation. The doc tree carries eval annotations
    /// on each node that was visited by the evaluator.
    Rule {
        doc: Doc<Option<EvalAnn>>,
        line: Option<usize>,
    },
    /// Segment boundary for compound commands.
    SegmentHeader { command: String, decision: Decision },
    /// No rule matched; defaulting to ask.
    DefaultAsk { reason: String },
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
    pub trace: Vec<TraceEntry>,
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

impl CommandMatcher {
    pub fn to_doc(&self) -> Doc {
        match self {
            CommandMatcher::Exact(s) => {
                Doc::list(vec![Doc::atom("command"), Doc::atom(format!("\"{s}\""))])
            }
            CommandMatcher::Regex(re) => {
                Doc::list(vec![
                    Doc::atom("command"),
                    Doc::list(vec![Doc::atom("regex"), Doc::atom(format!("\"{}\"", re.as_str()))]),
                ])
            }
            CommandMatcher::List(names) => {
                let mut or_cs = vec![Doc::atom("or")];
                or_cs.extend(names.iter().map(|n| Doc::atom(format!("\"{n}\""))));
                Doc::list(vec![Doc::atom("command"), Doc::list(or_cs)])
            }
        }
    }
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
        let pe = PosExpr::one(Expr::Literal("x".into()));
        assert_eq!(format!("{:?}", pe), r#"Literal("x")"#);
    }

    #[test]
    fn pos_expr_debug_optional() {
        let pe = PosExpr { quantifier: Quantifier::Optional, expr: Expr::Wildcard };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("Optional("));
    }

    #[test]
    fn pos_expr_debug_one_or_more() {
        let pe = PosExpr { quantifier: Quantifier::OneOrMore, expr: Expr::Wildcard };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("OneOrMore("));
    }

    #[test]
    fn pos_expr_debug_zero_or_more() {
        let pe = PosExpr { quantifier: Quantifier::ZeroOrMore, expr: Expr::Wildcard };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("ZeroOrMore("));
    }

    // --- PosExpr delegation ---

    #[test]
    fn pos_expr_is_match_delegates() {
        let pe = PosExpr { quantifier: Quantifier::Optional, expr: Expr::Literal("x".into()) };
        assert!(pe.is_match("x"));
        assert!(!pe.is_match("y"));
    }

    #[test]
    fn pos_expr_is_wildcard_delegates() {
        assert!(PosExpr { quantifier: Quantifier::ZeroOrMore, expr: Expr::Wildcard }.is_wildcard());
        assert!(!PosExpr::one(Expr::Literal("x".into())).is_wildcard());
    }

    // --- has_effect for PosExpr paths ---

    #[test]
    fn has_effect_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::one(cond_expr)]);
        assert!(m.has_effect());
    }

    #[test]
    fn has_effect_exact_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::ExactPositional(vec![PosExpr { quantifier: Quantifier::Optional, expr: cond_expr }]);
        assert!(m.has_effect());
    }

    #[test]
    fn has_effect_positional_no_cond() {
        let m = ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)]);
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

    // --- to_doc tests ---

    fn doc_text(doc: &crate::doc::Doc) -> String {
        doc.fold(&|node, _ann| match node {
            crate::doc::DocF::Atom(s) => s,
            crate::doc::DocF::List(cs) => format!("({})", cs.join(" ")),
        })
    }

    #[test]
    fn effect_to_doc_no_reason() {
        let e = Effect { decision: Decision::Allow, reason: None };
        assert_eq!(doc_text(&e.to_doc()), "(effect :allow)");
    }

    #[test]
    fn effect_to_doc_with_reason() {
        let e = Effect { decision: Decision::Deny, reason: Some("bad".into()) };
        assert_eq!(doc_text(&e.to_doc()), r#"(effect :deny "bad")"#);
    }

    #[test]
    fn expr_to_doc_literal() {
        assert_eq!(doc_text(&Expr::Literal("foo".into()).to_doc()), r#""foo""#);
    }

    #[test]
    fn expr_to_doc_wildcard() {
        assert_eq!(doc_text(&Expr::Wildcard.to_doc()), "*");
    }

    #[test]
    fn expr_to_doc_regex() {
        let e = Expr::Regex(regex::Regex::new("^x$").unwrap());
        assert_eq!(doc_text(&e.to_doc()), r#"(regex "^x$")"#);
    }

    #[test]
    fn expr_to_doc_and() {
        let e = Expr::And(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        assert_eq!(doc_text(&e.to_doc()), r#"(and "a" "b")"#);
    }

    #[test]
    fn expr_to_doc_or() {
        let e = Expr::Or(vec![Expr::Literal("a".into())]);
        assert_eq!(doc_text(&e.to_doc()), r#"(or "a")"#);
    }

    #[test]
    fn expr_to_doc_not() {
        let e = Expr::Not(Box::new(Expr::Wildcard));
        assert_eq!(doc_text(&e.to_doc()), "(not *)");
    }

    #[test]
    fn expr_to_doc_cond() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        assert_eq!(doc_text(&e.to_doc()), r#"(cond ("x" (effect :allow)))"#);
    }

    #[test]
    fn pos_expr_to_doc_one() {
        let pe = PosExpr::one(Expr::Literal("x".into()));
        assert_eq!(doc_text(&pe.to_doc()), r#""x""#);
    }

    #[test]
    fn pos_expr_to_doc_optional() {
        let pe = PosExpr { quantifier: Quantifier::Optional, expr: Expr::Wildcard };
        assert_eq!(doc_text(&pe.to_doc()), "(? *)");
    }

    #[test]
    fn pos_expr_to_doc_one_or_more() {
        let pe = PosExpr { quantifier: Quantifier::OneOrMore, expr: Expr::Wildcard };
        assert_eq!(doc_text(&pe.to_doc()), "(+ *)");
    }

    #[test]
    fn pos_expr_to_doc_zero_or_more() {
        let pe = PosExpr { quantifier: Quantifier::ZeroOrMore, expr: Expr::Wildcard };
        assert_eq!(doc_text(&pe.to_doc()), "(* *)");
    }

    #[test]
    fn command_matcher_to_doc_exact() {
        let m = CommandMatcher::Exact("git".into());
        assert_eq!(doc_text(&m.to_doc()), r#"(command "git")"#);
    }

    #[test]
    fn command_matcher_to_doc_regex() {
        let m = CommandMatcher::Regex(regex::Regex::new("^git$").unwrap());
        assert_eq!(doc_text(&m.to_doc()), r#"(command (regex "^git$"))"#);
    }

    #[test]
    fn command_matcher_to_doc_list() {
        let m = CommandMatcher::List(vec!["a".into(), "b".into()]);
        assert_eq!(doc_text(&m.to_doc()), r#"(command (or "a" "b"))"#);
    }

    #[test]
    fn arg_matcher_to_doc_positional() {
        let m = ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)]);
        assert_eq!(doc_text(&m.to_doc()), "(positional *)");
    }

    #[test]
    fn arg_matcher_to_doc_exact_positional() {
        let m = ArgMatcher::ExactPositional(vec![PosExpr::one(Expr::Literal("x".into()))]);
        assert_eq!(doc_text(&m.to_doc()), r#"(exact "x")"#);
    }

    #[test]
    fn arg_matcher_to_doc_anywhere() {
        let m = ArgMatcher::Anywhere(vec![Expr::Literal("--flag".into())]);
        assert_eq!(doc_text(&m.to_doc()), r#"(anywhere "--flag")"#);
    }

    #[test]
    fn arg_matcher_to_doc_and() {
        let m = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![]),
            ArgMatcher::Positional(vec![]),
        ]);
        assert_eq!(doc_text(&m.to_doc()), "(and (positional) (positional))");
    }

    #[test]
    fn arg_matcher_to_doc_or() {
        let m = ArgMatcher::Or(vec![ArgMatcher::Positional(vec![])]);
        assert_eq!(doc_text(&m.to_doc()), "(or (positional))");
    }

    #[test]
    fn arg_matcher_to_doc_not() {
        let m = ArgMatcher::Not(Box::new(ArgMatcher::Positional(vec![])));
        assert_eq!(doc_text(&m.to_doc()), "(not (positional))");
    }

    #[test]
    fn arg_matcher_to_doc_cond() {
        let m = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![]),
                effect: Effect { decision: Decision::Allow, reason: None },
            }],
            fallback: None,
        });
        assert_eq!(doc_text(&m.to_doc()), "(cond ((positional) (effect :allow)))");
    }

    #[test]
    fn cond_arm_to_doc_with_fallback() {
        let arm = CondArm {
            branches: vec![],
            fallback: Some(Effect { decision: Decision::Deny, reason: Some("nope".into()) }),
        };
        assert_eq!(doc_text(&arm.to_doc()), r#"(cond (else (effect :deny "nope")))"#);
    }

    #[test]
    fn rule_body_to_doc_effect_only() {
        let body = RuleBody::Effect {
            matcher: None,
            effect: Effect { decision: Decision::Allow, reason: None },
        };
        let docs: Vec<String> = body.to_doc().iter().map(|d| doc_text(d)).collect();
        assert_eq!(docs, vec!["(effect :allow)"]);
    }

    #[test]
    fn rule_body_to_doc_effect_with_matcher() {
        let body = RuleBody::Effect {
            matcher: Some(ArgMatcher::Positional(vec![])),
            effect: Effect { decision: Decision::Deny, reason: None },
        };
        let docs: Vec<String> = body.to_doc().iter().map(|d| doc_text(d)).collect();
        assert_eq!(docs, vec!["(args (positional))", "(effect :deny)"]);
    }

    #[test]
    fn rule_body_to_doc_branching() {
        let body = RuleBody::Branching(ArgMatcher::Positional(vec![]));
        let docs: Vec<String> = body.to_doc().iter().map(|d| doc_text(d)).collect();
        assert_eq!(docs, vec!["(args (positional))"]);
    }

    #[test]
    fn rule_to_doc_full() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect { decision: Decision::Allow, reason: None },
            },
            checks: vec![],
            source_span: Span { start: 0, end: 0 },
        };
        assert_eq!(doc_text(&rule.to_doc()), r#"(rule (command "git") (effect :allow))"#);
    }
}

// ── Property-based tests ────────────────────────────────────────────

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_decision() -> impl Strategy<Value = Decision> {
        prop_oneof![
            Just(Decision::Allow),
            Just(Decision::Ask),
            Just(Decision::Deny),
        ]
    }

    // Expr strategy: recursive tree of Literal, Wildcard, And, Or, Not.
    // Skips Regex (hard to generate valid patterns) and Cond (has effects).
    fn arb_expr() -> impl Strategy<Value = Expr> {
        let leaf = prop_oneof![
            "[a-z]{1,8}".prop_map(Expr::Literal),
            Just(Expr::Wildcard),
        ];
        leaf.prop_recursive(4, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::And),
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::Or),
                inner.prop_map(|e| Expr::Not(Box::new(e))),
            ]
        })
    }

    // ── Decision lattice ────────────────────────────────────────────

    proptest! {
        #[test]
        fn decision_most_restrictive_is_commutative(a in arb_decision(), b in arb_decision()) {
            prop_assert_eq!(a.most_restrictive(b), b.most_restrictive(a));
        }

        #[test]
        fn decision_most_restrictive_is_associative(
            a in arb_decision(), b in arb_decision(), c in arb_decision()
        ) {
            prop_assert_eq!(
                a.most_restrictive(b).most_restrictive(c),
                a.most_restrictive(b.most_restrictive(c))
            );
        }

        #[test]
        fn decision_most_restrictive_is_idempotent(a in arb_decision()) {
            prop_assert_eq!(a.most_restrictive(a), a);
        }

        #[test]
        fn decision_deny_is_absorbing(a in arb_decision()) {
            prop_assert_eq!(a.most_restrictive(Decision::Deny), Decision::Deny);
        }

        #[test]
        fn decision_allow_is_identity(a in arb_decision()) {
            prop_assert_eq!(a.most_restrictive(Decision::Allow), a);
        }

        #[test]
        fn decision_most_restrictive_is_at_least_as_restrictive(
            a in arb_decision(), b in arb_decision()
        ) {
            let result = a.most_restrictive(b);
            prop_assert!(result >= a);
            prop_assert!(result >= b);
        }
    }

    // ── Expr boolean algebra ────────────────────────────────────────

    proptest! {
        #[test]
        fn expr_wildcard_matches_anything(s in "[a-z]{0,20}") {
            prop_assert!(Expr::Wildcard.is_match(&s));
        }

        #[test]
        fn expr_literal_matches_only_itself(s in "[a-z]{1,10}") {
            let e = Expr::Literal(s.clone());
            prop_assert!(e.is_match(&s));
        }

        #[test]
        fn expr_literal_rejects_different(a in "[a-z]{1,5}", b in "[a-z]{1,5}") {
            prop_assume!(a != b);
            prop_assert!(!Expr::Literal(a).is_match(&b));
        }

        #[test]
        fn expr_double_negation(e in arb_expr(), s in "[a-z]{1,10}") {
            let double_neg = Expr::Not(Box::new(Expr::Not(Box::new(e.clone()))));
            prop_assert_eq!(e.is_match(&s), double_neg.is_match(&s));
        }

        #[test]
        fn expr_and_is_commutative(a in arb_expr(), b in arb_expr(), s in "[a-z]{1,10}") {
            let ab = Expr::And(vec![a.clone(), b.clone()]);
            let ba = Expr::And(vec![b, a]);
            prop_assert_eq!(ab.is_match(&s), ba.is_match(&s));
        }

        #[test]
        fn expr_or_is_commutative(a in arb_expr(), b in arb_expr(), s in "[a-z]{1,10}") {
            let ab = Expr::Or(vec![a.clone(), b.clone()]);
            let ba = Expr::Or(vec![b, a]);
            prop_assert_eq!(ab.is_match(&s), ba.is_match(&s));
        }

        #[test]
        fn expr_de_morgan_not_and(a in arb_expr(), b in arb_expr(), s in "[a-z]{1,10}") {
            // !(a && b) == (!a || !b)
            let lhs = Expr::Not(Box::new(Expr::And(vec![a.clone(), b.clone()])));
            let rhs = Expr::Or(vec![
                Expr::Not(Box::new(a)),
                Expr::Not(Box::new(b)),
            ]);
            prop_assert_eq!(lhs.is_match(&s), rhs.is_match(&s));
        }

        #[test]
        fn expr_de_morgan_not_or(a in arb_expr(), b in arb_expr(), s in "[a-z]{1,10}") {
            // !(a || b) == (!a && !b)
            let lhs = Expr::Not(Box::new(Expr::Or(vec![a.clone(), b.clone()])));
            let rhs = Expr::And(vec![
                Expr::Not(Box::new(a)),
                Expr::Not(Box::new(b)),
            ]);
            prop_assert_eq!(lhs.is_match(&s), rhs.is_match(&s));
        }

        #[test]
        fn expr_and_with_wildcard_is_identity(e in arb_expr(), s in "[a-z]{1,10}") {
            let ew = Expr::And(vec![e.clone(), Expr::Wildcard]);
            prop_assert_eq!(e.is_match(&s), ew.is_match(&s));
        }

        #[test]
        fn expr_or_with_wildcard_always_matches(e in arb_expr(), s in "[a-z]{1,10}") {
            let ew = Expr::Or(vec![e, Expr::Wildcard]);
            prop_assert!(ew.is_match(&s));
        }
    }
}

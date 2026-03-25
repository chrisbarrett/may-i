// Shared domain types for authorization rules and configuration.

use crate::doc::Doc;
use crate::span::{offset_to_line_col, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextValue {
    Present,
    Scalar(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextFacts {
    values: std::collections::BTreeMap<String, ContextValue>,
}

impl ContextFacts {
    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.values.get(key)
    }

    pub fn get_scalar(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(ContextValue::Scalar(value)) => Some(value.as_str()),
            Some(ContextValue::Present) | None => None,
        }
    }

    pub fn insert_present(&mut self, key: impl Into<String>) {
        self.values.insert(key.into(), ContextValue::Present);
    }

    pub fn insert_scalar(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .insert(key.into(), ContextValue::Scalar(value.into()));
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.values.extend(other.values.clone());
        merged
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ContextValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub message: String,
    pub span: Span,
    pub help: Option<String>,
}

fn quote_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[derive(Clone)]
pub enum FactPattern {
    Literal(String),
    Wildcard,
    Regex(regex::Regex),
    And(Vec<FactPattern>),
    Or(Vec<FactPattern>),
    Not(Box<FactPattern>),
}

impl FactPattern {
    pub fn to_doc(&self) -> Doc {
        match self {
            FactPattern::Literal(value) => Doc::atom(quote_string(value)),
            FactPattern::Wildcard => Doc::atom("*"),
            FactPattern::Regex(regex) => Doc::list(vec![
                Doc::atom("regex"),
                Doc::atom(quote_string(regex.as_str())),
            ]),
            FactPattern::And(patterns) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(patterns.iter().map(FactPattern::to_doc));
                Doc::list(cs)
            }
            FactPattern::Or(patterns) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(patterns.iter().map(FactPattern::to_doc));
                Doc::list(cs)
            }
            FactPattern::Not(pattern) => Doc::list(vec![Doc::atom("not"), pattern.to_doc()]),
        }
    }

    pub fn to_source(&self) -> String {
        match self {
            FactPattern::Literal(value) => quote_string(value),
            FactPattern::Wildcard => "*".into(),
            FactPattern::Regex(regex) => format!("(regex {})", quote_string(regex.as_str())),
            FactPattern::And(patterns) => {
                let parts = patterns
                    .iter()
                    .map(FactPattern::to_source)
                    .collect::<Vec<_>>();
                format!("(and {})", parts.join(" "))
            }
            FactPattern::Or(patterns) => {
                let parts = patterns
                    .iter()
                    .map(FactPattern::to_source)
                    .collect::<Vec<_>>();
                format!("(or {})", parts.join(" "))
            }
            FactPattern::Not(pattern) => format!("(not {})", pattern.to_source()),
        }
    }

    pub fn is_literal(&self) -> bool {
        matches!(self, FactPattern::Literal(_))
    }
}

impl std::fmt::Debug for FactPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FactPattern::Literal(value) => f.debug_tuple("Literal").field(value).finish(),
            FactPattern::Wildcard => f.write_str("Wildcard"),
            FactPattern::Regex(regex) => f.debug_tuple("Regex").field(&regex.as_str()).finish(),
            FactPattern::And(patterns) => f.debug_tuple("And").field(patterns).finish(),
            FactPattern::Or(patterns) => f.debug_tuple("Or").field(patterns).finish(),
            FactPattern::Not(pattern) => f.debug_tuple("Not").field(pattern).finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum FactQuery {
    Presence { key: String, vector_syntax: bool },
    Value { key: String, pattern: FactPattern },
}

impl FactQuery {
    pub fn key(&self) -> &str {
        match self {
            FactQuery::Presence { key, .. } | FactQuery::Value { key, .. } => key,
        }
    }

    pub fn to_doc(&self) -> Doc {
        match self {
            FactQuery::Presence {
                key,
                vector_syntax: false,
            } => Doc::atom(key.clone()),
            FactQuery::Presence {
                key,
                vector_syntax: true,
            } => Doc::vector(vec![Doc::atom(key.clone())]),
            FactQuery::Value { key, pattern } => {
                Doc::vector(vec![Doc::atom(key.clone()), pattern.to_doc()])
            }
        }
    }

    pub fn to_source(&self) -> String {
        match self {
            FactQuery::Presence {
                key,
                vector_syntax: false,
            } => key.clone(),
            FactQuery::Presence {
                key,
                vector_syntax: true,
            } => format!("[{key}]"),
            FactQuery::Value { key, pattern } => format!("[{key} {}]", pattern.to_source()),
        }
    }
}

#[derive(Clone)]
pub enum ContextExpr {
    Alias(String),
    Has(FactQuery),
    And(Vec<ContextExpr>),
    Or(Vec<ContextExpr>),
    Not(Box<ContextExpr>),
}

impl ContextExpr {
    pub fn to_doc(&self) -> Doc {
        match self {
            ContextExpr::Alias(name) => Doc::atom(name.clone()),
            ContextExpr::Has(query) => Doc::list(vec![Doc::atom("has"), query.to_doc()]),
            ContextExpr::And(exprs) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(exprs.iter().map(|expr| expr.to_doc()));
                Doc::list(cs)
            }
            ContextExpr::Or(exprs) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(exprs.iter().map(|expr| expr.to_doc()));
                Doc::list(cs)
            }
            ContextExpr::Not(expr) => Doc::list(vec![Doc::atom("not"), expr.to_doc()]),
        }
    }
}

impl std::fmt::Debug for ContextExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextExpr::Alias(name) => f.debug_tuple("Alias").field(name).finish(),
            ContextExpr::Has(query) => f.debug_tuple("Has").field(query).finish(),
            ContextExpr::And(exprs) => f.debug_tuple("And").field(exprs).finish(),
            ContextExpr::Or(exprs) => f.debug_tuple("Or").field(exprs).finish(),
            ContextExpr::Not(expr) => f.debug_tuple("Not").field(expr).finish(),
        }
    }
}

/// Boolean expression for fact predicates within argument matching.
/// Unlike ContextExpr, BoolExpr is used within ArgMatcher for runtime fact checks.
#[derive(Debug, Clone)]
pub enum BoolExpr {
    /// Check if a fact exists or matches a pattern.
    Has(FactQuery),
    /// All sub-expressions must be true.
    And(Vec<BoolExpr>),
    /// Any sub-expression must be true.
    Or(Vec<BoolExpr>),
    /// Inverts the result.
    Not(Box<BoolExpr>),
}

impl BoolExpr {
    pub fn to_doc(&self) -> Doc {
        match self {
            BoolExpr::Has(query) => Doc::list(vec![Doc::atom("has"), query.to_doc()]),
            BoolExpr::And(exprs) => {
                let mut cs = vec![Doc::atom("and")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                Doc::list(cs)
            }
            BoolExpr::Or(exprs) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                Doc::list(cs)
            }
            BoolExpr::Not(expr) => Doc::list(vec![Doc::atom("not"), expr.to_doc()]),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WrapperPattern {
    pub expr: Expr,
    pub bind_fact: Option<String>,
}

impl WrapperPattern {
    pub fn is_match(&self, text: &str) -> bool {
        self.expr.is_match(text)
    }

    pub fn is_wildcard(&self) -> bool {
        self.expr.is_wildcard()
    }

    pub fn to_doc(&self) -> Doc {
        match &self.bind_fact {
            Some(key) => Doc::atom(format!("[{key} {}]", self.expr)),
            None => self.expr.to_doc(),
        }
    }
}

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

impl ToDoc for Effect {
    fn to_doc(&self) -> Doc {
        let mut cs = vec![
            Doc::atom("effect"),
            Doc::atom(format!(":{}", self.decision)),
        ];
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

/// Trait for types that can be converted to a Doc representation.
pub trait ToDoc {
    fn to_doc(&self) -> Doc;
}

/// An expression that matches a single string, optionally carrying effects.
///
/// This type uses the fixpoint-of-functor pattern internally, enabling generic
/// traversals via the `ExprF` base functor.
#[derive(Clone)]
pub enum Expr<E: std::fmt::Debug + ToDoc = Effect> {
    /// Exact string match.
    Literal(String),
    /// Regex match.
    Regex(regex::Regex),
    /// Matches any string.
    Wildcard,
    /// All sub-expressions must match.
    And(Vec<Expr<E>>),
    /// Any sub-expression must match.
    Or(Vec<Expr<E>>),
    /// Inverts the match result.
    Not(Box<Expr<E>>),
    /// Branches with effects; first matching branch wins.
    Cond(Vec<ExprBranch<E>>),
}

/// Base functor for expression types.
///
/// `ExprF<R, E>` represents the shape of an expression where:
/// - `R` is the type of recursive children
/// - `E` is the effect type carried in `Cond` branches
///
/// This enables generic traversals via `map`, `map_ref`, and `map_ref_mut` operations.
#[derive(Debug)]
pub enum ExprF<R, E: std::fmt::Debug + ToDoc = Effect> {
    /// Exact string match.
    Literal(String),
    /// Regex match.
    Regex(regex::Regex),
    /// Matches any string.
    Wildcard,
    /// All sub-expressions must match.
    And(Vec<R>),
    /// Any sub-expression must match.
    Or(Vec<R>),
    /// Inverts the match result.
    Not(Box<R>),
    /// Branches with effects; first matching branch wins.
    Cond(Vec<ExprBranchF<R, E>>),
}

impl<R: Clone, E: std::fmt::Debug + ToDoc + Clone> Clone for ExprF<R, E> {
    fn clone(&self) -> Self {
        match self {
            ExprF::Literal(s) => ExprF::Literal(s.clone()),
            ExprF::Regex(re) => ExprF::Regex(re.clone()),
            ExprF::Wildcard => ExprF::Wildcard,
            ExprF::And(children) => ExprF::And(children.clone()),
            ExprF::Or(children) => ExprF::Or(children.clone()),
            ExprF::Not(child) => ExprF::Not(child.clone()),
            ExprF::Cond(branches) => ExprF::Cond(branches.clone()),
        }
    }
}

/// A branch in an expression-level cond.
#[derive(Debug, Clone)]
pub struct ExprBranch<E: std::fmt::Debug + ToDoc = Effect> {
    pub test: Expr<E>,
    pub effect: E,
}

/// Base functor for expression branches.
///
/// `ExprBranchF<R, E>` represents a branch in a conditional expression
/// where `R` is the recursive test expression type.
#[derive(Debug, Clone)]
pub struct ExprBranchF<R, E: std::fmt::Debug + ToDoc = Effect> {
    pub test: R,
    pub effect: E,
}

impl<R, E: std::fmt::Debug + ToDoc + Clone> ExprF<R, E> {
    /// Map over the recursive children of this expression.
    ///
    /// Transforms an `ExprF<R, E>` into `ExprF<S, E>` by applying `f` to each
    /// recursive child of type `R` to produce a value of type `S`.
    pub fn map<S>(self, mut f: impl FnMut(R) -> S) -> ExprF<S, E> {
        match self {
            ExprF::Literal(s) => ExprF::Literal(s),
            ExprF::Regex(re) => ExprF::Regex(re),
            ExprF::Wildcard => ExprF::Wildcard,
            ExprF::And(children) => ExprF::And(children.into_iter().map(f).collect()),
            ExprF::Or(children) => ExprF::Or(children.into_iter().map(f).collect()),
            ExprF::Not(child) => ExprF::Not(Box::new(f(*child))),
            ExprF::Cond(branches) => {
                ExprF::Cond(branches.into_iter().map(|b| b.map(&mut f)).collect())
            }
        }
    }

    /// Map over the recursive children by reference.
    ///
    /// Like `map`, but operates on references to children without consuming self.
    pub fn map_ref<S>(&self, mut f: impl FnMut(&R) -> S) -> ExprF<S, E> {
        match self {
            ExprF::Literal(s) => ExprF::Literal(s.clone()),
            ExprF::Regex(re) => ExprF::Regex(re.clone()),
            ExprF::Wildcard => ExprF::Wildcard,
            ExprF::And(children) => ExprF::And(children.iter().map(&mut f).collect()),
            ExprF::Or(children) => ExprF::Or(children.iter().map(&mut f).collect()),
            ExprF::Not(child) => ExprF::Not(Box::new(f(child))),
            ExprF::Cond(branches) => {
                ExprF::Cond(branches.iter().map(|b| b.map_ref(&mut f)).collect())
            }
        }
    }

    /// Map over the recursive children by mutable reference.
    ///
    /// Like `map`, but operates on mutable references to children.
    pub fn map_ref_mut<S>(&mut self, mut f: impl FnMut(&mut R) -> S) -> ExprF<S, E> {
        match self {
            ExprF::Literal(s) => ExprF::Literal(s.clone()),
            ExprF::Regex(re) => ExprF::Regex(re.clone()),
            ExprF::Wildcard => ExprF::Wildcard,
            ExprF::And(children) => ExprF::And(children.iter_mut().map(&mut f).collect()),
            ExprF::Or(children) => ExprF::Or(children.iter_mut().map(&mut f).collect()),
            ExprF::Not(child) => ExprF::Not(Box::new(f(child))),
            ExprF::Cond(branches) => {
                ExprF::Cond(branches.iter_mut().map(|b| b.map_ref_mut(&mut f)).collect())
            }
        }
    }
}

impl<E: std::fmt::Debug + ToDoc> Expr<E> {
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

    /// Find the effect associated with a matching condition branch.
    ///
    /// Searches through And, Or, and Not expressions to find a Cond branch
    /// where the test matches the given text. Returns the effect if found.
    pub fn find_effect(&self, text: &str) -> Option<&E> {
        match self {
            Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => None,
            Expr::And(exprs) => exprs.iter().find_map(|e| e.find_effect(text)),
            Expr::Or(exprs) => exprs.iter().find_map(|e| e.find_effect(text)),
            Expr::Not(expr) => expr.find_effect(text),
            Expr::Cond(branches) => branches
                .iter()
                .find(|b| b.test.is_match(text))
                .map(|b| &b.effect),
        }
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
                if exprs.len() > 4 {
                    Doc::broken_list(cs)
                } else {
                    Doc::list(cs)
                }
            }
            Expr::Or(exprs) => {
                let mut cs = vec![Doc::atom("or")];
                cs.extend(exprs.iter().map(|e| e.to_doc()));
                if exprs.len() > 4 {
                    Doc::broken_list(cs)
                } else {
                    Doc::list(cs)
                }
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

impl<E: std::fmt::Debug + ToDoc> std::fmt::Debug for Expr<E> {
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

impl<R, E: std::fmt::Debug + ToDoc + Clone> ExprBranchF<R, E> {
    /// Map over the test expression in this branch.
    pub fn map<S>(self, f: &mut impl FnMut(R) -> S) -> ExprBranchF<S, E> {
        ExprBranchF {
            test: f(self.test),
            effect: self.effect,
        }
    }

    /// Map over the test expression by reference.
    pub fn map_ref<S>(&self, f: &mut impl FnMut(&R) -> S) -> ExprBranchF<S, E> {
        ExprBranchF {
            test: f(&self.test),
            effect: self.effect.clone(),
        }
    }

    /// Map over the test expression by mutable reference.
    pub fn map_ref_mut<S>(&mut self, f: &mut impl FnMut(&mut R) -> S) -> ExprBranchF<S, E> {
        ExprBranchF {
            test: f(&mut self.test),
            effect: self.effect.clone(),
        }
    }
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
    pub checks: Vec<Check>,
    pub warnings: Vec<ConfigWarning>,
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
    pub context: Option<ContextExpr>,
    pub body: RuleBody,
    pub checks: Vec<Check>,
    pub source_span: Span,
}

/// What a rule does when the command name matches.
#[derive(Debug, Clone)]
pub enum RuleBody {
    /// Apply a fixed effect, optionally requiring an arg matcher to succeed first.
    Effect {
        matcher: Option<ArgMatcher>,
        effect: Effect,
    },
    /// The matcher tree itself determines the effect (via embedded Cond branches).
    Branching(ArgMatcher),
}

impl RuleBody {
    pub fn to_doc(&self) -> Vec<Doc> {
        match self {
            RuleBody::Effect {
                matcher: None,
                effect,
            } => {
                vec![effect.to_doc()]
            }
            RuleBody::Effect {
                matcher: Some(m),
                effect,
            } => {
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
        if let Some(context) = &self.context {
            cs.push(Doc::list(vec![Doc::atom("context"), context.to_doc()]));
        }
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

/// Polymorphic predicate for conditional branches in ArgMatcher.
/// Allows mixing matchers, string expressions, and fact predicates.
#[derive(Debug, Clone)]
pub enum MatcherCondPredicate {
    /// Full ArgMatcher for complex matching.
    Matcher(Box<ArgMatcher>),
    /// String expression for simple value testing.
    Expr(Expr),
    /// Boolean expression for fact checking.
    BoolExpr(BoolExpr),
}

impl MatcherCondPredicate {
    pub fn to_doc(&self) -> Doc {
        match self {
            MatcherCondPredicate::Matcher(m) => m.to_doc(),
            MatcherCondPredicate::Expr(e) => e.to_doc(),
            MatcherCondPredicate::BoolExpr(b) => b.to_doc(),
        }
    }
}

/// A branch in a polymorphic conditional (cond/when/unless/if).
#[derive(Debug, Clone)]
pub struct PolymorphicCondBranch {
    pub predicate: MatcherCondPredicate,
    pub effect: Effect,
}

/// The arms and optional fallback of a polymorphic conditional.
#[derive(Debug, Clone)]
pub struct PolymorphicCondArm {
    pub branches: Vec<PolymorphicCondBranch>,
    pub fallback: Option<Effect>,
}

impl PolymorphicCondArm {
    pub fn to_doc(&self, keyword: &str) -> Doc {
        let mut cs = vec![Doc::atom(keyword)];
        for b in &self.branches {
            cs.push(Doc::list(vec![b.predicate.to_doc(), b.effect.to_doc()]));
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
        Self {
            quantifier: Quantifier::One,
            expr,
        }
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
    /// Fact predicate check - evaluates BoolExpr against context facts.
    Has(BoolExpr),
    /// When form: first matching polymorphic branch wins, with optional else fallback.
    When(PolymorphicCondArm),
    /// Unless form: branches match when predicate is false.
    Unless(PolymorphicCondArm),
    /// If form: single branch with test and optional else.
    If {
        test: Box<MatcherCondPredicate>,
        then_effect: Effect,
        else_effect: Option<Effect>,
    },
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
            ArgMatcher::Has(expr) => expr.to_doc(),
            ArgMatcher::When(arm) => arm.to_doc("when"),
            ArgMatcher::Unless(arm) => arm.to_doc("unless"),
            ArgMatcher::If {
                test,
                then_effect,
                else_effect,
            } => {
                let mut cs = vec![Doc::atom("if"), test.to_doc(), then_effect.to_doc()];
                if let Some(else_eff) = else_effect {
                    cs.push(else_eff.to_doc());
                }
                Doc::list(cs)
            }
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
            // Has doesn't carry effects - it's just a boolean check
            ArgMatcher::Has(_) => false,
            // When/Unless/If all carry effects in their branches
            ArgMatcher::When(_arm) => true,
            ArgMatcher::Unless(_arm) => true,
            ArgMatcher::If { .. } => true,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextFailureReason {
    Absent,
    PresentWithoutScalar,
    ValueMismatch,
    PatternMismatch,
}

impl ContextFailureReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContextFailureReason::Absent => "absent",
            ContextFailureReason::PresentWithoutScalar => "present_without_scalar",
            ContextFailureReason::ValueMismatch => "value_mismatch",
            ContextFailureReason::PatternMismatch => "pattern_mismatch",
        }
    }
}

#[derive(Debug, Clone)]
pub enum FactPatternEval {
    Literal {
        value: String,
        evaluated: bool,
        matched: bool,
    },
    Wildcard {
        evaluated: bool,
        matched: bool,
    },
    Regex {
        pattern: String,
        evaluated: bool,
        matched: bool,
    },
    And {
        evaluated: bool,
        matched: bool,
        children: Vec<FactPatternEval>,
    },
    Or {
        evaluated: bool,
        matched: bool,
        children: Vec<FactPatternEval>,
    },
    Not {
        evaluated: bool,
        matched: bool,
        child: Box<FactPatternEval>,
    },
}

/// A single step in a wrapper definition.
#[derive(Debug, Clone)]
pub enum WrapperStep {
    /// Validate positional (non-flag) args match patterns in order.
    /// If `capture` is true, the inner command starts immediately after
    /// the last matched positional in the original arg list.
    Positional {
        patterns: Vec<WrapperPattern>,
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
    ExprVsArg {
        arg: String,
        matched: bool,
    },
    /// Quantified pattern consumed some arguments.
    Quantifier {
        count: usize,
        matched: bool,
    },
    /// Required positional argument was missing.
    Missing,
    /// Token-anywhere search against all args.
    Anywhere {
        args: Vec<String>,
        matched: bool,
    },
    ContextResult(bool),
    ContextHasPresence {
        key: String,
        source: String,
        matched: bool,
    },
    ContextHasExact {
        key: String,
        source: String,
        expected: String,
        actual: Option<String>,
        matched: bool,
        reason: Option<ContextFailureReason>,
        search_needle: String,
    },
    ContextHasPattern {
        key: String,
        source: String,
        pattern_source: String,
        pattern: FactPattern,
        pattern_eval: FactPatternEval,
        actual: Option<String>,
        matched: bool,
        reason: Option<ContextFailureReason>,
        search_needle: String,
    },
    /// A conditional branch was selected (expr-level or matcher-level).
    CondBranch {
        decision: Decision,
    },
    /// A conditional else/fallback was selected.
    CondElse {
        decision: Decision,
    },
    /// Exact positional vector equality: patterns vs actual args.
    ExactArgs {
        patterns: Vec<String>,
        args: Vec<String>,
        matched: bool,
    },
    /// Exact positional had leftover arguments.
    ExactRemainder {
        count: usize,
    },
    /// Overall args match result.
    ArgsResult(bool),
    /// The effect produced by this rule.
    RuleEffect {
        decision: Decision,
        reason: Option<String>,
    },
    /// No rule matched; defaulting to ask.
    DefaultAsk,
}

/// A single entry in an evaluation trace.
#[derive(Debug, Clone)]
pub enum TraceEntry {
    /// An annotated rule evaluation. The doc tree carries eval annotations
    /// on each node that was visited by the evaluator.
    Rule {
        doc: Box<Doc<Option<EvalAnn>>>,
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
            CommandMatcher::Regex(re) => Doc::list(vec![
                Doc::atom("command"),
                Doc::list(vec![
                    Doc::atom("regex"),
                    Doc::atom(format!("\"{}\"", re.as_str())),
                ]),
            ]),
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
    pub context: ContextFacts,
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
    // Note: Many is_match properties are covered by property tests in prop_tests module.
    // These unit tests serve as concrete examples and cover edge cases not in proptests.

    #[test]
    fn expr_regex_match() {
        let e: Expr = Expr::Regex(regex::Regex::new("^foo.*bar$").unwrap());
        assert!(e.is_match("fooXbar"));
    }

    #[test]
    fn expr_regex_no_match() {
        let e: Expr = Expr::Regex(regex::Regex::new("^foo.*bar$").unwrap());
        assert!(!e.is_match("baz"));
    }

    #[test]
    fn expr_and_all_match() {
        let e: Expr = Expr::And(vec![
            Expr::Regex(regex::Regex::new("^f").unwrap()),
            Expr::Regex(regex::Regex::new("o$").unwrap()),
        ]);
        assert!(e.is_match("foo"));
    }

    #[test]
    fn expr_and_one_fails() {
        let e: Expr = Expr::And(vec![
            Expr::Regex(regex::Regex::new("^f").unwrap()),
            Expr::Regex(regex::Regex::new("z$").unwrap()),
        ]);
        assert!(!e.is_match("foo"));
    }

    #[test]
    fn expr_cond_matches_branch() {
        let e: Expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("a".into()),
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        assert!(e.is_match("a"));
        assert!(!e.is_match("b"));
    }

    // --- Expr::is_wildcard ---

    #[test]
    fn expr_is_wildcard() {
        assert!(Expr::<Effect>::Wildcard.is_wildcard());
    }

    #[test]
    fn expr_literal_not_wildcard() {
        assert!(!Expr::<Effect>::Literal("hello".into()).is_wildcard());
    }

    #[test]
    fn expr_regex_not_wildcard() {
        assert!(!Expr::<Effect>::Regex(regex::Regex::new("^.*$").unwrap()).is_wildcard());
    }

    // --- Expr::Debug ---

    #[test]
    fn expr_debug_literal() {
        let e: Expr = Expr::Literal("hello".into());
        assert_eq!(format!("{:?}", e), r#"Literal("hello")"#);
    }

    #[test]
    fn expr_debug_regex() {
        let e: Expr = Expr::Regex(regex::Regex::new("^foo$").unwrap());
        assert_eq!(format!("{:?}", e), r#"Regex("^foo$")"#);
    }

    #[test]
    fn expr_debug_wildcard() {
        assert_eq!(format!("{:?}", Expr::<Effect>::Wildcard), "Wildcard");
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
        let e: Expr = Expr::And(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("And("));
    }

    #[test]
    fn expr_debug_or() {
        let e: Expr = Expr::Or(vec![Expr::Literal("a".into())]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Or("));
    }

    #[test]
    fn expr_debug_not() {
        let e: Expr = Expr::Not(Box::new(Expr::Wildcard));
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Not("));
    }

    #[test]
    fn expr_debug_cond() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
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
        let pe = PosExpr {
            quantifier: Quantifier::Optional,
            expr: Expr::Wildcard,
        };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("Optional("));
    }

    #[test]
    fn pos_expr_debug_one_or_more() {
        let pe = PosExpr {
            quantifier: Quantifier::OneOrMore,
            expr: Expr::Wildcard,
        };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("OneOrMore("));
    }

    #[test]
    fn pos_expr_debug_zero_or_more() {
        let pe = PosExpr {
            quantifier: Quantifier::ZeroOrMore,
            expr: Expr::Wildcard,
        };
        let dbg = format!("{:?}", pe);
        assert!(dbg.starts_with("ZeroOrMore("));
    }

    // --- PosExpr delegation ---

    #[test]
    fn pos_expr_is_match_delegates() {
        let pe = PosExpr {
            quantifier: Quantifier::Optional,
            expr: Expr::Literal("x".into()),
        };
        assert!(pe.is_match("x"));
        assert!(!pe.is_match("y"));
    }

    #[test]
    fn pos_expr_is_wildcard_delegates() {
        assert!(PosExpr {
            quantifier: Quantifier::ZeroOrMore,
            expr: Expr::Wildcard
        }
        .is_wildcard());
        assert!(!PosExpr::one(Expr::Literal("x".into())).is_wildcard());
    }

    // --- has_effect for PosExpr paths ---

    #[test]
    fn has_effect_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::one(cond_expr)]);
        assert!(m.has_effect());
    }

    #[test]
    fn has_effect_exact_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        let m = ArgMatcher::ExactPositional(vec![PosExpr {
            quantifier: Quantifier::Optional,
            expr: cond_expr,
        }]);
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
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        let e = Expr::And(vec![cond]);
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Allow);
        assert!(e.find_effect("y").is_none());
    }

    #[test]
    fn find_effect_through_or() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect {
                decision: Decision::Deny,
                reason: None,
            },
        }]);
        let e = Expr::Or(vec![Expr::Literal("z".into()), cond]);
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Deny);
    }

    #[test]
    fn find_effect_through_not() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect {
                decision: Decision::Ask,
                reason: None,
            },
        }]);
        let e = Expr::Not(Box::new(cond));
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Ask);
    }

    // --- to_doc tests ---

    fn doc_text(doc: &crate::doc::Doc) -> String {
        doc.fold(&|node, _ann| match node {
            crate::doc::DocF::Atom(s) => s,
            crate::doc::DocF::List(cs) => format!("({})", cs.join(" ")),
            crate::doc::DocF::Vector(cs) => format!("[{}]", cs.join(" ")),
        })
    }

    #[test]
    fn fact_pattern_to_doc_regex() {
        let pattern = FactPattern::Regex(regex::Regex::new("^prod-").unwrap());
        assert_eq!(doc_text(&pattern.to_doc()), r#"(regex "^prod-")"#);
    }

    #[test]
    fn fact_query_to_doc_preserves_presence_sugar() {
        let bare = FactQuery::Presence {
            key: ":via/ssh".into(),
            vector_syntax: false,
        };
        let vector = FactQuery::Presence {
            key: ":via/ssh".into(),
            vector_syntax: true,
        };
        assert_eq!(doc_text(&bare.to_doc()), ":via/ssh");
        assert_eq!(doc_text(&vector.to_doc()), "[:via/ssh]");
    }

    #[test]
    fn context_has_to_doc_uses_vector_queries() {
        let expr = ContextExpr::Has(FactQuery::Value {
            key: ":opencode/agent".into(),
            pattern: FactPattern::Literal("build".into()),
        });
        assert_eq!(
            doc_text(&expr.to_doc()),
            r#"(has [:opencode/agent "build"])"#
        );
    }

    #[test]
    fn fact_pattern_to_source_handles_boolean_forms() {
        let pattern = FactPattern::And(vec![
            FactPattern::Wildcard,
            FactPattern::Not(Box::new(FactPattern::Literal("build".into()))),
        ]);
        assert_eq!(pattern.to_source(), r#"(and * (not "build"))"#);
    }

    #[test]
    fn fact_query_to_source_and_key_for_value_query() {
        let query = FactQuery::Value {
            key: ":ssh/host".into(),
            pattern: FactPattern::Regex(regex::Regex::new("^prod-").unwrap()),
        };
        assert_eq!(query.key(), ":ssh/host");
        assert_eq!(query.to_source(), r#"[:ssh/host (regex "^prod-")]"#);
    }

    #[test]
    fn fact_pattern_literal_to_doc_escapes_special_chars() {
        let pattern = FactPattern::Literal("line1\n\t\"two\"".into());
        assert_eq!(doc_text(&pattern.to_doc()), r#""line1\n\t\"two\"""#);
    }

    #[test]
    fn fact_query_presence_to_source_preserves_bare_and_vector_forms() {
        let bare = FactQuery::Presence {
            key: ":client/opencode".into(),
            vector_syntax: false,
        };
        let vector = FactQuery::Presence {
            key: ":client/opencode".into(),
            vector_syntax: true,
        };
        assert_eq!(bare.to_source(), ":client/opencode");
        assert_eq!(vector.to_source(), "[:client/opencode]");
    }

    #[test]
    fn effect_to_doc_no_reason() {
        let e = Effect {
            decision: Decision::Allow,
            reason: None,
        };
        assert_eq!(doc_text(&e.to_doc()), "(effect :allow)");
    }

    #[test]
    fn effect_to_doc_with_reason() {
        let e = Effect {
            decision: Decision::Deny,
            reason: Some("bad".into()),
        };
        assert_eq!(doc_text(&e.to_doc()), r#"(effect :deny "bad")"#);
    }

    #[test]
    fn expr_to_doc_literal() {
        assert_eq!(
            doc_text(&Expr::<Effect>::Literal("foo".into()).to_doc()),
            r#""foo""#
        );
    }

    #[test]
    fn expr_to_doc_wildcard() {
        assert_eq!(doc_text(&Expr::<Effect>::Wildcard.to_doc()), "*");
    }

    #[test]
    fn expr_to_doc_regex() {
        let e: Expr = Expr::Regex(regex::Regex::new("^x$").unwrap());
        assert_eq!(doc_text(&e.to_doc()), r#"(regex "^x$")"#);
    }

    #[test]
    fn expr_to_doc_and() {
        let e: Expr = Expr::And(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        assert_eq!(doc_text(&e.to_doc()), r#"(and "a" "b")"#);
    }

    #[test]
    fn expr_to_doc_or() {
        let e: Expr = Expr::Or(vec![Expr::Literal("a".into())]);
        assert_eq!(doc_text(&e.to_doc()), r#"(or "a")"#);
    }

    #[test]
    fn expr_to_doc_not() {
        let e: Expr = Expr::Not(Box::new(Expr::Wildcard));
        assert_eq!(doc_text(&e.to_doc()), "(not *)");
    }

    #[test]
    fn expr_to_doc_cond() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
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
        let pe = PosExpr {
            quantifier: Quantifier::Optional,
            expr: Expr::Wildcard,
        };
        assert_eq!(doc_text(&pe.to_doc()), "(? *)");
    }

    #[test]
    fn pos_expr_to_doc_one_or_more() {
        let pe = PosExpr {
            quantifier: Quantifier::OneOrMore,
            expr: Expr::Wildcard,
        };
        assert_eq!(doc_text(&pe.to_doc()), "(+ *)");
    }

    #[test]
    fn pos_expr_to_doc_zero_or_more() {
        let pe = PosExpr {
            quantifier: Quantifier::ZeroOrMore,
            expr: Expr::Wildcard,
        };
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
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            }],
            fallback: None,
        });
        assert_eq!(
            doc_text(&m.to_doc()),
            "(cond ((positional) (effect :allow)))"
        );
    }

    #[test]
    fn cond_arm_to_doc_with_fallback() {
        let arm = CondArm {
            branches: vec![],
            fallback: Some(Effect {
                decision: Decision::Deny,
                reason: Some("nope".into()),
            }),
        };
        assert_eq!(
            doc_text(&arm.to_doc()),
            r#"(cond (else (effect :deny "nope")))"#
        );
    }

    #[test]
    fn rule_body_to_doc_effect_only() {
        let body = RuleBody::Effect {
            matcher: None,
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        };
        let docs: Vec<String> = body.to_doc().iter().map(|d| doc_text(d)).collect();
        assert_eq!(docs, vec!["(effect :allow)"]);
    }

    #[test]
    fn rule_body_to_doc_effect_with_matcher() {
        let body = RuleBody::Effect {
            matcher: Some(ArgMatcher::Positional(vec![])),
            effect: Effect {
                decision: Decision::Deny,
                reason: None,
            },
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
            context: None,
            body: RuleBody::Effect {
                matcher: None,
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            checks: vec![],
            source_span: Span { start: 0, end: 0 },
        };
        assert_eq!(
            doc_text(&rule.to_doc()),
            r#"(rule (command "git") (effect :allow))"#
        );
    }

    // --- Additional tests for uncovered lines ---

    #[test]
    fn context_facts_get_scalar_returns_none_for_present() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":test");
        assert_eq!(facts.get_scalar(":test"), None);
    }

    #[test]
    fn context_facts_get_scalar_returns_none_for_missing() {
        let facts = ContextFacts::default();
        assert_eq!(facts.get_scalar(":missing"), None);
    }

    #[test]
    fn context_facts_iter_empty() {
        let facts = ContextFacts::default();
        assert_eq!(facts.iter().count(), 0);
    }

    #[test]
    fn context_facts_iter_with_values() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":a");
        facts.insert_scalar(":b", "value");
        let collected: Vec<_> = facts.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn fact_pattern_is_literal_true() {
        let p = FactPattern::Literal("test".into());
        assert!(p.is_literal());
    }

    #[test]
    fn fact_pattern_is_literal_false() {
        let p = FactPattern::Wildcard;
        assert!(!p.is_literal());
    }

    #[test]
    fn fact_pattern_debug_regex() {
        let p = FactPattern::Regex(regex::Regex::new("^test$").unwrap());
        let dbg = format!("{:?}", p);
        assert!(dbg.contains("Regex"));
        assert!(dbg.contains("^test$"));
    }

    #[test]
    fn fact_pattern_debug_and() {
        let p = FactPattern::And(vec![FactPattern::Wildcard]);
        let dbg = format!("{:?}", p);
        assert!(dbg.starts_with("And("));
    }

    #[test]
    fn fact_pattern_debug_or() {
        let p = FactPattern::Or(vec![]);
        let dbg = format!("{:?}", p);
        assert!(dbg.starts_with("Or("));
    }

    #[test]
    fn fact_pattern_debug_not() {
        let p = FactPattern::Not(Box::new(FactPattern::Wildcard));
        let dbg = format!("{:?}", p);
        assert!(dbg.starts_with("Not("));
    }

    #[test]
    fn fact_query_presence_vector_syntax() {
        let q = FactQuery::Presence {
            key: ":test".into(),
            vector_syntax: true,
        };
        assert_eq!(doc_text(&q.to_doc()), "[:test]");
    }

    #[test]
    fn context_expr_alias_to_doc() {
        let e = ContextExpr::Alias("my-alias".into());
        assert_eq!(doc_text(&e.to_doc()), "my-alias");
    }

    #[test]
    fn context_expr_debug_alias() {
        let e = ContextExpr::Alias("test".into());
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Alias("));
    }

    #[test]
    fn bool_expr_to_doc_and_empty() {
        let e = BoolExpr::And(vec![]);
        let doc = e.to_doc();
        assert_eq!(doc_text(&doc), "(and)");
    }

    #[test]
    fn bool_expr_to_doc_or_empty() {
        let e = BoolExpr::Or(vec![]);
        let doc = e.to_doc();
        assert_eq!(doc_text(&doc), "(or)");
    }

    #[test]
    fn wrapper_pattern_is_wildcard_true() {
        let wp = WrapperPattern {
            expr: Expr::Wildcard,
            bind_fact: None,
        };
        assert!(wp.is_wildcard());
    }

    #[test]
    fn wrapper_pattern_is_wildcard_false() {
        let wp = WrapperPattern {
            expr: Expr::Literal("x".into()),
            bind_fact: None,
        };
        assert!(!wp.is_wildcard());
    }

    #[test]
    fn wrapper_pattern_to_doc_with_bind() {
        let wp = WrapperPattern {
            expr: Expr::Literal("test".into()),
            bind_fact: Some(":fact".into()),
        };
        assert_eq!(doc_text(&wp.to_doc()), "[:fact \"test\"]");
    }

    #[test]
    fn source_info_line_of() {
        let info = SourceInfo {
            filename: "test.lisp".into(),
            content: "line1\nline2\nline3".into(),
        };
        assert_eq!(info.line_of(Span { start: 0, end: 5 }), 1);
        assert_eq!(info.line_of(Span { start: 7, end: 12 }), 2);
    }

    #[test]
    fn expr_display_literal() {
        let e = Expr::Literal("hello".into());
        assert_eq!(format!("{}", e), "\"hello\"");
    }

    #[test]
    fn expr_display_wildcard() {
        assert_eq!(format!("{}", Expr::Wildcard), "*");
    }

    #[test]
    fn expr_display_regex() {
        let e = Expr::Regex(regex::Regex::new("^test$").unwrap());
        assert_eq!(format!("{}", e), "(regex \"^test$\")");
    }

    #[test]
    fn expr_display_and() {
        let e = Expr::And(vec![]);
        assert_eq!(format!("{}", e), "(and)");
    }

    #[test]
    fn expr_display_or() {
        let e = Expr::Or(vec![Expr::Literal("a".into())]);
        assert_eq!(format!("{}", e), "(or \"a\")");
    }

    #[test]
    fn expr_display_not() {
        let e: Expr = Expr::Not(Box::new(Expr::Wildcard));
        assert_eq!(format!("{}", e), "(not *)");
    }

    #[test]
    fn expr_to_doc_and_many_children() {
        let e: Expr = Expr::And(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
            Expr::Literal("c".into()),
            Expr::Literal("d".into()),
            Expr::Literal("e".into()),
        ]);
        let doc = e.to_doc();
        // Should use broken_list for > 4 children
        let _ = doc_text(&doc);
    }

    #[test]
    fn expr_to_doc_or_many_children() {
        let e: Expr = Expr::Or(vec![
            Expr::Literal("a".into()),
            Expr::Literal("b".into()),
            Expr::Literal("c".into()),
            Expr::Literal("d".into()),
            Expr::Literal("e".into()),
        ]);
        let doc = e.to_doc();
        // Should use broken_list for > 4 children
        let _ = doc_text(&doc);
    }

    #[test]
    fn quantifier_min_one() {
        assert_eq!(Quantifier::One.min(), 1);
        assert_eq!(Quantifier::OneOrMore.min(), 1);
    }

    #[test]
    fn quantifier_min_zero() {
        assert_eq!(Quantifier::Optional.min(), 0);
        assert_eq!(Quantifier::ZeroOrMore.min(), 0);
    }

    #[test]
    fn quantifier_is_repeating() {
        assert!(Quantifier::OneOrMore.is_repeating());
        assert!(Quantifier::ZeroOrMore.is_repeating());
        assert!(!Quantifier::One.is_repeating());
        assert!(!Quantifier::Optional.is_repeating());
    }

    #[test]
    fn arg_matcher_has_effect_anywhere_with_cond() {
        let m = ArgMatcher::Anywhere(vec![Expr::Cond(vec![])]);
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_not_with_cond() {
        let inner = ArgMatcher::Positional(vec![PosExpr::one(Expr::Cond(vec![]))]);
        let m = ArgMatcher::Not(Box::new(inner));
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_cond() {
        // Cond has_effect returns true if any branch's matcher has_effect
        let m = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Cond(vec![]))]),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            }],
            fallback: None,
        });
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_has() {
        let m = ArgMatcher::Has(BoolExpr::And(vec![]));
        assert!(!m.has_effect());
    }

    #[test]
    fn arg_matcher_to_doc_exact_positional_empty() {
        let m = ArgMatcher::ExactPositional(vec![]);
        assert_eq!(doc_text(&m.to_doc()), "(exact)");
    }

    #[test]
    fn arg_matcher_to_doc_cond_with_fallback() {
        let m = ArgMatcher::Cond(CondArm {
            branches: vec![],
            fallback: Some(Effect {
                decision: Decision::Deny,
                reason: None,
            }),
        });
        assert_eq!(doc_text(&m.to_doc()), "(cond (else (effect :deny)))");
    }

    #[test]
    fn arg_matcher_to_doc_when() {
        let m = ArgMatcher::When(PolymorphicCondArm {
            branches: vec![],
            fallback: None,
        });
        assert_eq!(doc_text(&m.to_doc()), "(when)");
    }

    #[test]
    fn arg_matcher_to_doc_unless() {
        let m = ArgMatcher::Unless(PolymorphicCondArm {
            branches: vec![],
            fallback: None,
        });
        assert_eq!(doc_text(&m.to_doc()), "(unless)");
    }

    #[test]
    fn arg_matcher_to_doc_if_no_else() {
        let m = ArgMatcher::If {
            test: Box::new(MatcherCondPredicate::Expr(Expr::Wildcard)),
            then_effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
            else_effect: None,
        };
        assert_eq!(doc_text(&m.to_doc()), "(if * (effect :allow))");
    }

    #[test]
    fn polymorphic_cond_arm_to_doc_with_fallback() {
        let arm = PolymorphicCondArm {
            branches: vec![],
            fallback: Some(Effect {
                decision: Decision::Ask,
                reason: None,
            }),
        };
        assert_eq!(doc_text(&arm.to_doc("when")), "(when (else (effect :ask)))");
    }

    #[test]
    fn matcher_cond_predicate_to_doc_matcher() {
        let p = MatcherCondPredicate::Matcher(Box::new(ArgMatcher::Has(BoolExpr::And(vec![]))));
        assert_eq!(doc_text(&p.to_doc()), "(and)");
    }

    #[test]
    fn matcher_cond_predicate_to_doc_expr() {
        let p = MatcherCondPredicate::Expr(Expr::Wildcard);
        assert_eq!(doc_text(&p.to_doc()), "*");
    }

    #[test]
    fn matcher_cond_predicate_to_doc_bool_expr() {
        let p = MatcherCondPredicate::BoolExpr(BoolExpr::Has(FactQuery::Presence {
            key: ":test".into(),
            vector_syntax: false,
        }));
        assert_eq!(doc_text(&p.to_doc()), "(has :test)");
    }

    #[test]
    fn context_failure_reason_as_str() {
        assert_eq!(ContextFailureReason::Absent.as_str(), "absent");
        assert_eq!(
            ContextFailureReason::PresentWithoutScalar.as_str(),
            "present_without_scalar"
        );
        assert_eq!(
            ContextFailureReason::ValueMismatch.as_str(),
            "value_mismatch"
        );
        assert_eq!(
            ContextFailureReason::PatternMismatch.as_str(),
            "pattern_mismatch"
        );
    }

    #[test]
    fn config_warning_fields() {
        let warning = ConfigWarning {
            message: "test".into(),
            span: Span { start: 0, end: 5 },
            help: Some("help text".into()),
        };
        assert_eq!(warning.message, "test");
        assert_eq!(warning.span.start, 0);
        assert!(warning.help.is_some());
    }

    #[test]
    fn eval_result_with_trace() {
        let mut result = EvalResult::new(Decision::Allow, Some("reason".into()));
        result.trace.push(TraceEntry::DefaultAsk {
            reason: "test".into(),
        });
        assert_eq!(result.trace.len(), 1);
    }

    #[test]
    fn trace_entry_variants() {
        let entry1 = TraceEntry::SegmentHeader {
            command: "test".into(),
            decision: Decision::Allow,
        };
        let entry2 = TraceEntry::DefaultAsk {
            reason: "test".into(),
        };
        // Just verify they compile
        let _ = format!("{:?}", entry1);
        let _ = format!("{:?}", entry2);
    }

    #[test]
    fn check_struct_fields() {
        let check = Check {
            command: "test".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            source_span: Span { start: 0, end: 5 },
        };
        assert_eq!(check.command, "test");
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
        let leaf = prop_oneof!["[a-z]{1,8}".prop_map(Expr::Literal), Just(Expr::Wildcard),];
        leaf.prop_recursive(4, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::And),
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::Or),
                inner.prop_map(|e| Expr::Not(Box::new(e))),
            ]
        })
    }

    // Expr strategy with simple effect type (SimpleEffect) to test Cond branches.
    // This allows testing expressions with effects without the complexity of the Effect type.
    #[derive(Debug, Clone)]
    struct SimpleEffect(pub u32);

    impl ToDoc for SimpleEffect {
        fn to_doc(&self) -> Doc {
            Doc::atom(format!("effect_{}", self.0))
        }
    }

    fn arb_expr_with_cond() -> impl Strategy<Value = Expr<SimpleEffect>> {
        let leaf = prop_oneof!["[a-z]{1,8}".prop_map(Expr::Literal), Just(Expr::Wildcard),];
        leaf.prop_recursive(4, 16, 4, |inner| {
            prop_oneof![
                // And, Or, Not as before
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::And),
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::Or),
                inner.clone().prop_map(|e| Expr::Not(Box::new(e))),
                // Cond branches with SimpleEffect (u32) effects
                prop::collection::vec(
                    (inner.clone(), 0u32..100).prop_map(|(test, effect)| {
                        ExprBranch {
                            test,
                            effect: SimpleEffect(effect),
                        }
                    }),
                    1..4
                )
                .prop_map(Expr::Cond),
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
            prop_assert!(Expr::<Effect>::Wildcard.is_match(&s));
        }

        #[test]
        fn expr_literal_matches_only_itself(s in "[a-z]{1,10}") {
            let e: Expr = Expr::Literal(s.clone());
            prop_assert!(e.is_match(&s));
        }

        #[test]
        fn expr_literal_rejects_different(a in "[a-z]{1,5}", b in "[a-z]{1,5}") {
            prop_assume!(a != b);
            prop_assert!(!Expr::<Effect>::Literal(a).is_match(&b));
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

        // ── Expr with Cond branches (using SimpleEffect) ────────────

        #[test]
        fn expr_cond_matches_first_matching_branch(e in arb_expr_with_cond(), s in "[a-z]{1,10}") {
            // Cond matches if any branch's test matches
            if let Expr::Cond(branches) = &e {
                let expected = branches.iter().any(|b| b.test.is_match(&s));
                prop_assert_eq!(e.is_match(&s), expected);
            }
        }

        #[test]
        fn expr_cond_preserves_branch_order(e in arb_expr_with_cond(), s in "[a-z]{1,10}") {
            // Branch order shouldn't matter for is_match (only for find_effect)
            if let Expr::Cond(branches) = &e {
                if branches.len() >= 2 {
                    // Create reversed version
                    let mut reversed_branches = branches.clone();
                    reversed_branches.reverse();
                    let reversed = Expr::Cond(reversed_branches);
                    prop_assert_eq!(e.is_match(&s), reversed.is_match(&s));
                }
            }
        }

        #[test]
        fn expr_nested_cond_with_and_or(e in arb_expr_with_cond(), s in "[a-z]{1,10}") {
            // Cond with And/Or children (or even nested Cond) should still work correctly
            if let Expr::Cond(branches) = &e {
                for branch in branches {
                    // Branch test should have consistent matching behavior
                    let matches = branch.test.is_match(&s);
                    // Verify by recomputing manually
                    let double_check = match &branch.test {
                        Expr::Literal(lit) => lit == &s,
                        Expr::Wildcard => true,
                        Expr::Regex(_) => unreachable!("Regex not in test strategy"),
                        Expr::And(children) => children.iter().all(|c| c.is_match(&s)),
                        Expr::Or(children) => children.iter().any(|c| c.is_match(&s)),
                        Expr::Not(inner) => !inner.is_match(&s),
                        Expr::Cond(nested_branches) => {
                            nested_branches.iter().any(|nb| nb.test.is_match(&s))
                        }
                    };
                    prop_assert_eq!(matches, double_check);
                }
            }
        }

        #[test]
        fn expr_cond_not_with_cond_children(e in arb_expr_with_cond(), s in "[a-z]{1,10}") {
            // Not(Cond(...)) should invert Cond matching
            if let Expr::Cond(_) = &e {
                let negated = Expr::Not(Box::new(e.clone()));
                prop_assert_eq!(e.is_match(&s), !negated.is_match(&s));
            }
        }
    }

    // ── Functor laws ─────────────────────────────────────────────────

    // Simple strategy for testing functor operations - just literals and wildcards
    // (avoiding recursive structure due to trait bound complexity)
    fn arb_simple_exprf() -> impl Strategy<Value = ExprF<String, Effect>> {
        prop_oneof![
            "[a-z]{1,8}".prop_map(ExprF::Literal),
            Just(ExprF::Wildcard),
            prop::collection::vec("[a-z]{1,5}", 1..4).prop_map(ExprF::And),
            prop::collection::vec("[a-z]{1,5}", 1..4).prop_map(ExprF::Or),
        ]
    }

    proptest! {
        // Functor identity law: map(id) == id
        // For any functor f, f.map(|x| x) should be equivalent to f
        #[test]
        fn exprf_map_identity(functor in arb_simple_exprf()) {
            let mapped = functor.map_ref(|x| x.clone());

            // Verify variant is preserved
            let variant_matches = matches!(
                (&functor, &mapped),
                (ExprF::Literal(_), ExprF::Literal(_)) |
                (ExprF::Wildcard, ExprF::Wildcard) |
                (ExprF::And(_), ExprF::And(_)) |
                (ExprF::Or(_), ExprF::Or(_))
            );
            prop_assert!(variant_matches, "Identity map changed the variant type");

            // Verify children count is preserved
            match (&functor, &mapped) {
                (ExprF::And(c1), ExprF::And(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                (ExprF::Or(c1), ExprF::Or(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                _ => {}
            }
        }

        // Functor composition law: map(f).map(g) == map(|x| g(f(x)))
        // Mapping with f then g should equal mapping with their composition
        #[test]
        fn exprf_map_composition(functor in arb_simple_exprf()) {
            // f: duplicate the string (takes &String, returns String)
            let f = |x: &String| format!("{}_{}", x, x);
            // g: wrap in brackets (takes &String, returns String)
            let g = |x: &String| format!("[{}]", x);

            // Composition: apply f then g separately
            // First map_ref applies f, but returns ExprF<String> with String children
            // Second map_ref needs to work on String (not &String), so we use map
            let step1: ExprF<String, Effect> = functor.map_ref(f);
            // Use map for second step since we have owned Strings
            let composed_separate = step1.map(|x| g(&x));

            // Composition: apply g(f(x)) directly
            let composed_together = functor.map_ref(|x| g(&f(x)));

            // Both should produce the same structure
            match (&composed_separate, &composed_together) {
                (ExprF::Literal(s1), ExprF::Literal(s2)) => prop_assert_eq!(s1, s2),
                (ExprF::Wildcard, ExprF::Wildcard) => prop_assert!(true),
                (ExprF::And(c1), ExprF::And(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                (ExprF::Or(c1), ExprF::Or(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                _ => prop_assert!(false, "Mismatched variants after composition"),
            }
        }

        // Functor preserves structure: map only transforms children, not shape
        #[test]
        fn exprf_map_preserves_structure(functor in arb_simple_exprf()) {
            let transformed = functor.map_ref(|x| format!("mapped_{}", x));

            // Shape should be identical (same variant, same child count)
            let shape_matches = match (&functor, &transformed) {
                (ExprF::Literal(_), ExprF::Literal(_)) => true,
                (ExprF::Wildcard, ExprF::Wildcard) => true,
                (ExprF::And(c1), ExprF::And(c2)) => c1.len() == c2.len(),
                (ExprF::Or(c1), ExprF::Or(c2)) => c1.len() == c2.len(),
                _ => false,
            };
            prop_assert!(shape_matches, "Map changed the functor structure");
        }

        // map vs map_ref equivalence: both should produce same result
        #[test]
        fn exprf_map_and_map_ref_equivalent(functor in arb_simple_exprf()) {
            let transform = |x: &String| format!("xformed_{}", x);

            // Using map_ref (takes &R, returns S)
            let via_ref = functor.map_ref(transform);

            // Using map (takes R, returns S) - need to clone first
            let cloned = functor.clone();
            let via_owned = cloned.map(|x| transform(&x));

            // Check that both produce same variant and structure
            match (&via_ref, &via_owned) {
                (ExprF::Literal(s1), ExprF::Literal(s2)) => prop_assert_eq!(s1, s2),
                (ExprF::Wildcard, ExprF::Wildcard) => prop_assert!(true),
                (ExprF::And(c1), ExprF::And(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                (ExprF::Or(c1), ExprF::Or(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                _ => prop_assert!(false, "map and map_ref produced different structures"),
            }
        }

        // Test that map_ref_mut behaves like map_ref for non-mutating operations
        #[test]
        fn exprf_map_ref_mut_matches_map_ref(functor in arb_simple_exprf()) {
            let mut cloned = functor.clone();
            let via_mut = cloned.map_ref_mut(|x| format!("mut_{}", x));
            let via_ref = functor.map_ref(|x| format!("mut_{}", x));

            match (&via_mut, &via_ref) {
                (ExprF::Literal(s1), ExprF::Literal(s2)) => prop_assert_eq!(s1, s2),
                (ExprF::Wildcard, ExprF::Wildcard) => prop_assert!(true),
                (ExprF::And(c1), ExprF::And(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                (ExprF::Or(c1), ExprF::Or(c2)) => prop_assert_eq!(c1.len(), c2.len()),
                _ => prop_assert!(false, "map_ref_mut and map_ref produced different results"),
            }
        }
    }

    // --- Tests for Keyword type ---

    #[test]
    fn keyword_valid_constructible() {
        let kw = Keyword::new(":ssh/host").unwrap();
        assert_eq!(kw.as_str(), ":ssh/host");
    }

    #[test]
    fn keyword_rejects_non_namespaced() {
        let result = Keyword::new("ssh");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must start with"));
    }

    #[test]
    fn keyword_rejects_empty() {
        let result = Keyword::new("");
        assert!(result.is_err());
    }

    #[test]
    fn keyword_rejects_whitespace() {
        let result = Keyword::new("  ");
        assert!(result.is_err());
    }

    #[test]
    fn keyword_to_doc_produces_atom() {
        let kw = Keyword::new(":env").unwrap();
        let doc = kw.to_doc();
        // Should render as just ":env"
        assert_eq!(doc.render(80), ":env");
    }

    // --- Tests for Expr::Bind with Keyword ---

    #[test]
    fn expr_bind_with_keyword() {
        use crate::types::Expr;

        // Create a Bind expression with a Keyword
        let kw = Keyword::new(":ssh/host").unwrap();
        let bind_expr = Expr::Bind {
            key: kw,
            expr: Box::new(Expr::Wildcard),
        };

        match bind_expr {
            Expr::Bind { key, expr } => {
                assert_eq!(key.as_str(), ":ssh/host");
                assert!(matches!(expr.as_ref(), Expr::Wildcard));
            }
            _ => panic!("expected Expr::Bind"),
        }
    }
}

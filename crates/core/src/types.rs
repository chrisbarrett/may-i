// Shared domain types for authorization rules and configuration.

use crate::doc::Doc;
use crate::span::{offset_to_line_col, Span};

/// A validated keyword string that starts with `:`.
///
/// Keywords are used as fact keys in bindings and queries.
/// The validation ensures correctness by construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Keyword(String);

impl Keyword {
    /// Create a new keyword from a string.
    ///
    /// Returns an error if the string does not start with `:`.
    pub fn new(s: impl Into<String>) -> Result<Self, String> {
        let s = s.into();
        if s.starts_with(':') {
            Ok(Keyword(s))
        } else {
            Err(format!("keyword must start with ':', got '{}'", s))
        }
    }

    /// Create a new keyword without validation (for internal use).
    ///
    /// # Safety
    /// The caller must ensure the string starts with `:`.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Keyword(s.into())
    }

    /// Get the string representation of the keyword.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner String.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for Keyword {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ToDoc for Keyword {
    fn to_doc(&self) -> Doc {
        Doc::atom(self.0.clone())
    }
}

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
    #[coverage(off)]
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
    #[coverage(off)]
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
    #[coverage(off)]
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
    #[coverage(off)]
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
    /// Bind the matched value to a fact key.
    Bind { key: Keyword, expr: Box<Expr<E>> },
}

/// A branch in an expression-level cond.
#[derive(Debug, Clone)]
pub struct ExprBranch<E: std::fmt::Debug + ToDoc = Effect> {
    pub test: Expr<E>,
    pub effect: E,
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
            Expr::Bind { expr, .. } => expr.is_match(text),
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
            Expr::Bind { expr, .. } => expr.find_effect(text),
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
            Expr::Bind { key, expr } => Doc::vector(vec![key.to_doc(), expr.to_doc()]),
        }
    }
}

impl std::fmt::Display for Expr {
    #[coverage(off)]
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
            Expr::Bind { key, expr } => {
                write!(f, "[{key} {expr}]")
            }
        }
    }
}

impl<E: std::fmt::Debug + ToDoc> std::fmt::Debug for Expr<E> {
    #[coverage(off)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Literal(s) => f.debug_tuple("Literal").field(s).finish(),
            Expr::Regex(re) => f.debug_tuple("Regex").field(&re.as_str()).finish(),
            Expr::Wildcard => write!(f, "Wildcard"),
            Expr::And(exprs) => f.debug_tuple("And").field(exprs).finish(),
            Expr::Or(exprs) => f.debug_tuple("Or").field(exprs).finish(),
            Expr::Not(expr) => f.debug_tuple("Not").field(expr).finish(),
            Expr::Cond(branches) => f.debug_tuple("Cond").field(branches).finish(),
            Expr::Bind { key, expr } => f
                .debug_struct("Bind")
                .field("key", key)
                .field("expr", expr)
                .finish(),
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
    #[coverage(off)]
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
        Expr::Bind { expr, .. } => has_expr_effect(expr),
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
    #[coverage(off)]
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
    use crate::doc::DocF;
    use crate::pattern::PositionalArg;

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

    // --- Expr::is_match Bind variant (line 450) ---

    #[test]
    fn expr_bind_delegates_to_inner() {
        let e: Expr = Expr::Bind {
            key: Keyword::new_unchecked(":test"),
            expr: Box::new(Expr::Literal("inner".into())),
        };
        assert!(e.is_match("inner"));
        assert!(!e.is_match("other"));
    }

    #[test]
    fn expr_bind_with_wildcard_matches_anything() {
        let e: Expr = Expr::Bind {
            key: Keyword::new_unchecked(":host"),
            expr: Box::new(Expr::Wildcard),
        };
        assert!(e.is_match("anything"));
        assert!(e.is_match("something"));
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

    // --- Effect::Display (lines 389-394) ---

    #[test]
    fn effect_display_allow_without_reason() {
        let e = Effect {
            decision: Decision::Allow,
            reason: None,
        };
        assert_eq!(format!("{}", e), "(effect :allow)");
    }

    #[test]
    fn effect_display_ask_with_reason() {
        let e = Effect {
            decision: Decision::Ask,
            reason: Some("confirm this".into()),
        };
        assert_eq!(format!("{}", e), "(effect :ask \"confirm this\")");
    }

    #[test]
    fn effect_display_deny_with_special_chars() {
        let e = Effect {
            decision: Decision::Deny,
            reason: Some("danger\"ous".into()),
        };
        assert_eq!(format!("{}", e), "(effect :deny \"danger\"ous\")");
    }

    // --- Keyword::Display (lines 46-47) ---

    #[test]
    fn keyword_display_shows_value() {
        let kw = Keyword::new(":test/key").unwrap();
        assert_eq!(format!("{}", kw), ":test/key");
    }

    #[test]
    fn keyword_display_preserves_colon() {
        let kw = Keyword::new_unchecked(":my-keyword");
        assert_eq!(format!("{}", kw), ":my-keyword");
    }

    // --- Expr::Display Bind variant (lines 660-661) ---

    #[test]
    fn expr_display_bind_with_keyword() {
        let kw = Keyword::new_unchecked(":host");
        let e = Expr::Bind {
            key: kw,
            expr: Box::new(Expr::Wildcard),
        };
        assert_eq!(format!("{}", e), "[:host *]");
    }

    #[test]
    fn expr_display_bind_with_literal() {
        let kw = Keyword::new_unchecked(":env");
        let e = Expr::Bind {
            key: kw,
            expr: Box::new(Expr::Literal("prod".into())),
        };
        assert_eq!(format!("{}", e), "[:env \"prod\"]");
    }

    // --- BoolExpr::to_doc for Or/Not/Has (lines 305-317) ---

    #[test]
    fn bool_expr_to_doc_has_presence() {
        let e = BoolExpr::Has(FactQuery::Presence {
            key: ":via/ssh".into(),
            vector_syntax: false,
        });
        assert_eq!(doc_text(&e.to_doc()), "(has :via/ssh)");
    }

    #[test]
    fn bool_expr_to_doc_has_value() {
        let e = BoolExpr::Has(FactQuery::Value {
            key: ":opencode/agent".into(),
            pattern: FactPattern::Literal("build".into()),
        });
        assert_eq!(doc_text(&e.to_doc()), "(has [:opencode/agent \"build\"])");
    }

    #[test]
    fn bool_expr_to_doc_not() {
        let inner = BoolExpr::Has(FactQuery::Presence {
            key: ":restricted".into(),
            vector_syntax: false,
        });
        let e = BoolExpr::Not(Box::new(inner));
        assert_eq!(doc_text(&e.to_doc()), "(not (has :restricted))");
    }

    #[test]
    fn bool_expr_to_doc_or_with_multiple() {
        let e = BoolExpr::Or(vec![
            BoolExpr::Has(FactQuery::Presence {
                key: ":a".into(),
                vector_syntax: false,
            }),
            BoolExpr::Has(FactQuery::Presence {
                key: ":b".into(),
                vector_syntax: false,
            }),
        ]);
        assert_eq!(doc_text(&e.to_doc()), "(or (has :a) (has :b))");
    }

    // --- ContextFacts additional tests (lines 30-31, 40-41) ---

    #[test]
    fn context_facts_get_returns_present() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":test");
        assert!(matches!(facts.get(":test"), Some(ContextValue::Present)));
    }

    #[test]
    fn context_facts_get_returns_scalar() {
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":key", "value");
        assert!(matches!(facts.get(":key"), Some(ContextValue::Scalar(v)) if v == "value"));
    }

    #[test]
    fn context_facts_get_returns_none_for_missing() {
        let facts = ContextFacts::default();
        assert_eq!(facts.get(":missing"), None);
    }

    #[test]
    fn context_facts_get_scalar_returns_value() {
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":env", "production");
        assert_eq!(facts.get_scalar(":env"), Some("production"));
    }

    // --- Keyword tests (lines 30-31, 40-41) ---

    #[test]
    fn keyword_into_string_consumes() {
        let kw = Keyword::new_unchecked(":my-keyword");
        let s: String = kw.into_string();
        assert_eq!(s, ":my-keyword");
    }

    #[test]
    fn keyword_new_unchecked_accepts_any() {
        // Even though it's unsafe, it should accept any string
        let kw = Keyword::new_unchecked(":special-chars-123");
        assert_eq!(kw.as_str(), ":special-chars-123");
    }

    // --- FactQuery additional tests (lines 116, 119) ---

    #[test]
    fn fact_query_key_for_presence() {
        let q = FactQuery::Presence {
            key: ":via/ssh".into(),
            vector_syntax: false,
        };
        assert_eq!(q.key(), ":via/ssh");
    }

    #[test]
    fn fact_query_key_for_value() {
        let q = FactQuery::Value {
            key: ":opencode/agent".into(),
            pattern: FactPattern::Wildcard,
        };
        assert_eq!(q.key(), ":opencode/agent");
    }

    // --- ContextExpr additional tests (lines 147-150, 152-155, 157, 279-282) ---

    #[test]
    fn context_expr_and_to_doc() {
        let e = ContextExpr::And(vec![
            ContextExpr::Alias("a".into()),
            ContextExpr::Alias("b".into()),
        ]);
        assert_eq!(doc_text(&e.to_doc()), "(and a b)");
    }

    #[test]
    fn context_expr_or_to_doc() {
        let e = ContextExpr::Or(vec![
            ContextExpr::Alias("x".into()),
            ContextExpr::Alias("y".into()),
        ]);
        assert_eq!(doc_text(&e.to_doc()), "(or x y)");
    }

    #[test]
    fn context_expr_not_to_doc() {
        let inner = ContextExpr::Alias("test".into());
        let e = ContextExpr::Not(Box::new(inner));
        assert_eq!(doc_text(&e.to_doc()), "(not test)");
    }

    #[test]
    fn context_expr_debug_and() {
        let e = ContextExpr::And(vec![]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("And("));
    }

    #[test]
    fn context_expr_debug_or() {
        let e = ContextExpr::Or(vec![]);
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Or("));
    }

    #[test]
    fn context_expr_debug_not() {
        let e = ContextExpr::Not(Box::new(ContextExpr::Alias("test".into())));
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Not("));
    }

    #[test]
    fn context_expr_debug_has() {
        let e = ContextExpr::Has(FactQuery::Presence {
            key: ":key".into(),
            vector_syntax: false,
        });
        let dbg = format!("{:?}", e);
        assert!(dbg.starts_with("Has("));
    }

    // --- Expr::to_doc Bind (line 627) ---

    #[test]
    fn expr_to_doc_bind() {
        let kw = Keyword::new_unchecked(":host");
        let e: Expr = Expr::Bind {
            key: kw,
            expr: Box::new(Expr::Literal("server".into())),
        };
        assert_eq!(doc_text(&e.to_doc()), "[:host \"server\"]");
    }

    // --- Expr::find_effect additional coverage (lines 589, 800) ---

    #[test]
    fn expr_find_effect_through_bind() {
        let cond = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("x".into()),
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        }]);
        let e = Expr::Bind {
            key: Keyword::new_unchecked(":key"),
            expr: Box::new(cond),
        };
        assert_eq!(e.find_effect("x").unwrap().decision, Decision::Allow);
    }

    #[test]
    fn expr_find_effect_bind_no_match() {
        let e: Expr = Expr::Bind {
            key: Keyword::new_unchecked(":key"),
            expr: Box::new(Expr::Literal("inner".into())),
        };
        assert!(e.find_effect("other").is_none());
    }

    // --- ArgMatcher::has_effect additional coverage (lines 1043-1044, 1051-1053, 1062-1064) ---

    #[test]
    fn arg_matcher_has_effect_and_with_cond() {
        let inner = ArgMatcher::Positional(vec![PosExpr::one(Expr::Cond(vec![]))]);
        let m = ArgMatcher::And(vec![inner]);
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_or_with_cond() {
        let inner = ArgMatcher::Positional(vec![PosExpr::one(Expr::Cond(vec![]))]);
        let m = ArgMatcher::Or(vec![inner]);
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_cond_without_effect() {
        let m = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)]),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            }],
            fallback: None,
        });
        // The Cond returns true because branches.iter().any(|b| b.matcher.has_effect())
        // but wait, the matcher is Positional with Wildcard which has no Cond...
        // Let me reconsider - the Cond's has_effect checks if ANY branch's matcher has_effect
        // The branch's matcher is Positional(vec![PosExpr::one(Expr::Wildcard)])
        // Positional checks pexprs.iter().any(|pe| has_expr_effect(&pe.expr))
        // has_expr_effect checks for Cond, And, Or, Not, Bind - but Wildcard is none of these
        // So this should NOT have effect... let me trace through more carefully
        assert!(!m.has_effect());
    }

    // --- ArgMatcher::has_effect for When/Unless/If (lines 912-914) ---

    #[test]
    fn arg_matcher_has_effect_when_returns_true() {
        let m = ArgMatcher::When(PolymorphicCondArm {
            branches: vec![],
            fallback: None,
        });
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_unless_returns_true() {
        let m = ArgMatcher::Unless(PolymorphicCondArm {
            branches: vec![],
            fallback: None,
        });
        assert!(m.has_effect());
    }

    #[test]
    fn arg_matcher_has_effect_if_returns_true() {
        let m = ArgMatcher::If {
            test: Box::new(MatcherCondPredicate::Expr(Expr::Wildcard)),
            then_effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
            else_effect: None,
        };
        assert!(m.has_effect());
    }

    // --- WrapperPattern tests (lines 338) ---

    #[test]
    fn wrapper_pattern_to_doc_no_bind() {
        let wp = WrapperPattern {
            expr: Expr::Literal("test".into()),
            bind_fact: None,
        };
        assert_eq!(doc_text(&wp.to_doc()), "\"test\"");
    }

    // --- FactPattern::to_doc tests (lines 458, 462-463, 465-466) ---

    #[test]
    fn fact_pattern_to_doc_and() {
        let p = FactPattern::And(vec![
            FactPattern::Literal("a".into()),
            FactPattern::Literal("b".into()),
        ]);
        assert_eq!(doc_text(&p.to_doc()), "(and \"a\" \"b\")");
    }

    #[test]
    fn fact_pattern_to_doc_or() {
        let p = FactPattern::Or(vec![
            FactPattern::Literal("x".into()),
            FactPattern::Wildcard,
        ]);
        assert_eq!(doc_text(&p.to_doc()), "(or \"x\" *)");
    }

    #[test]
    fn fact_pattern_to_doc_not() {
        let p = FactPattern::Not(Box::new(FactPattern::Literal("test".into())));
        assert_eq!(doc_text(&p.to_doc()), "(not \"test\")");
    }

    #[test]
    fn fact_pattern_to_doc_wildcard() {
        let p = FactPattern::Wildcard;
        assert_eq!(doc_text(&p.to_doc()), "*");
    }

    // --- ArgMatcher::to_doc tests (lines 497, 501-503, 507, 518, 522-524, 527-528, 539, 543-545, 548-549) ---

    #[test]
    fn arg_matcher_to_doc_has_bool_expr() {
        let m = ArgMatcher::Has(BoolExpr::Has(FactQuery::Presence {
            key: ":test".into(),
            vector_syntax: false,
        }));
        assert_eq!(doc_text(&m.to_doc()), "(has :test)");
    }

    // --- Rule::to_doc with context (line 800) ---

    #[test]
    fn rule_to_doc_with_context() {
        let rule = Rule {
            command: CommandMatcher::Exact("git".into()),
            context: Some(ContextExpr::Alias("ssh-context".into())),
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
            r#"(rule (command "git") (context ssh-context) (effect :allow))"#
        );
    }

    // --- CondArm with fallback (lines 874) ---

    #[test]
    fn polymorphic_cond_arm_to_doc_unless_with_fallback() {
        let arm = PolymorphicCondArm {
            branches: vec![],
            fallback: Some(Effect {
                decision: Decision::Deny,
                reason: None,
            }),
        };
        assert_eq!(
            doc_text(&arm.to_doc("unless")),
            "(unless (else (effect :deny)))"
        );
    }

    // --- EvalAnn and TraceEntry debug tests (lines 874, 1029, 1043-1044, 1051-1053, 1062-1064) ---

    #[test]
    fn eval_ann_variants_compile() {
        // Just verify all EvalAnn variants can be constructed
        let _: EvalAnn = EvalAnn::CommandMatch(true);
        let _: EvalAnn = EvalAnn::ExprVsArg {
            arg: "test".into(),
            matched: true,
        };
        let _: EvalAnn = EvalAnn::Quantifier {
            count: 1,
            matched: true,
        };
        let _: EvalAnn = EvalAnn::Missing;
        let _: EvalAnn = EvalAnn::Anywhere {
            args: vec![],
            matched: true,
        };
        let _: EvalAnn = EvalAnn::ContextResult(true);
        let _: EvalAnn = EvalAnn::ContextHasPresence {
            key: ":test".into(),
            source: "source".into(),
            matched: true,
        };
        let _: EvalAnn = EvalAnn::ContextHasExact {
            key: ":test".into(),
            source: "source".into(),
            expected: "exp".into(),
            actual: Some("act".into()),
            matched: false,
            reason: Some(ContextFailureReason::ValueMismatch),
            search_needle: "needle".into(),
        };
        let _: EvalAnn = EvalAnn::ContextHasPattern {
            key: ":test".into(),
            source: "source".into(),
            pattern_source: "pat".into(),
            pattern: FactPattern::Wildcard,
            pattern_eval: FactPatternEval::Wildcard {
                evaluated: true,
                matched: true,
            },
            actual: None,
            matched: true,
            reason: None,
            search_needle: "needle".into(),
        };
        let _: EvalAnn = EvalAnn::CondBranch {
            decision: Decision::Allow,
        };
        let _: EvalAnn = EvalAnn::CondElse {
            decision: Decision::Deny,
        };
        let _: EvalAnn = EvalAnn::ExactArgs {
            patterns: vec![],
            args: vec![],
            matched: true,
        };
        let _: EvalAnn = EvalAnn::ExactRemainder { count: 0 };
        let _: EvalAnn = EvalAnn::ArgsResult(true);
        let _: EvalAnn = EvalAnn::RuleEffect {
            decision: Decision::Ask,
            reason: Some("reason".into()),
        };
        let _: EvalAnn = EvalAnn::DefaultAsk;
    }

    #[test]
    fn trace_entry_rule_compiles() {
        // Create a Doc<Option<EvalAnn>> manually
        let annotated_doc = Doc {
            ann: Some(EvalAnn::DefaultAsk),
            node: DocF::Atom("test".into()),
            layout: crate::doc::LayoutHint::Auto,
            dimmed: false,
        };
        let _: TraceEntry = TraceEntry::Rule {
            doc: Box::new(annotated_doc),
            line: Some(1),
        };
    }

    #[test]
    fn trace_entry_segment_header_compiles() {
        let _: TraceEntry = TraceEntry::SegmentHeader {
            command: "cmd".into(),
            decision: Decision::Allow,
        };
    }

    #[test]
    fn trace_entry_default_ask_compiles() {
        let _: TraceEntry = TraceEntry::DefaultAsk {
            reason: "no rule matched".into(),
        };
    }

    // --- FactPatternEval tests (lines 1029) ---

    #[test]
    fn fact_pattern_eval_variants_compile() {
        let _: FactPatternEval = FactPatternEval::Literal {
            value: "test".into(),
            evaluated: true,
            matched: true,
        };
        let _: FactPatternEval = FactPatternEval::Wildcard {
            evaluated: true,
            matched: true,
        };
        let _: FactPatternEval = FactPatternEval::Regex {
            pattern: "^test$".into(),
            evaluated: true,
            matched: true,
        };
        let _: FactPatternEval = FactPatternEval::And {
            evaluated: true,
            matched: true,
            children: vec![],
        };
        let _: FactPatternEval = FactPatternEval::Or {
            evaluated: true,
            matched: true,
            children: vec![],
        };
        let _: FactPatternEval = FactPatternEval::Not {
            evaluated: true,
            matched: true,
            child: Box::new(FactPatternEval::Wildcard {
                evaluated: true,
                matched: false,
            }),
        };
    }

    // --- WrapperStep tests (lines 660-661, 677) ---

    #[test]
    fn wrapper_step_positional_compiles() {
        let _: WrapperStep = WrapperStep::Positional {
            patterns: vec![],
            capture: true,
        };
    }

    #[test]
    fn wrapper_step_flag_compiles() {
        let _: WrapperStep = WrapperStep::Flag { name: "--".into() };
    }

    // --- ContextFailureReason tests (lines 677, 679-680, 688, 690-691, 696, 698-699, 704, 706-707) ---

    #[test]
    fn context_failure_reason_all_variants() {
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

    // --- Config tests (lines 721-723) ---

    #[test]
    fn config_fields_accessible() {
        let config = Config {
            rules: vec![],
            wrappers: vec![],
            security: SecurityConfig::default(),
            checks: vec![],
            warnings: vec![],
            source_info: Some(SourceInfo {
                filename: "test.lisp".into(),
                content: "(rule)".into(),
            }),
        };
        assert!(config.source_info.is_some());
    }

    // --- SourceInfo::location_of tests (lines 721-723) ---

    #[test]
    fn source_info_location_of_first_line() {
        let info = SourceInfo {
            filename: "test.lisp".into(),
            content: "(rule)\n(second)".into(),
        };
        assert_eq!(info.location_of(Span { start: 0, end: 6 }), "test.lisp:1:1");
    }

    #[test]
    fn source_info_location_of_second_line() {
        let info = SourceInfo {
            filename: "test.lisp".into(),
            content: "(rule)\n(second)".into(),
        };
        assert_eq!(
            info.location_of(Span { start: 7, end: 15 }),
            "test.lisp:2:1"
        );
    }

    // --- FactPattern::to_source tests (lines 874) ---

    #[test]
    fn fact_pattern_to_source_wildcard() {
        let p = FactPattern::Wildcard;
        assert_eq!(p.to_source(), "*");
    }

    // --- FactQuery::to_source tests (lines 192) ---

    #[test]
    fn fact_query_to_source_presence_bare() {
        let q = FactQuery::Presence {
            key: ":test".into(),
            vector_syntax: false,
        };
        assert_eq!(q.to_source(), ":test");
    }

    #[test]
    fn fact_query_to_source_presence_vector() {
        let q = FactQuery::Presence {
            key: ":test".into(),
            vector_syntax: true,
        };
        assert_eq!(q.to_source(), "[:test]");
    }

    // --- RuleBody::to_doc edge cases (lines 260-263, 265-268, 270) ---

    #[test]
    fn rule_body_to_doc_effect_with_empty_matcher() {
        let body = RuleBody::Effect {
            matcher: Some(ArgMatcher::Positional(vec![])),
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        };
        let docs: Vec<String> = body.to_doc().iter().map(|d| doc_text(d)).collect();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0], "(args (positional))");
        assert_eq!(docs[1], "(effect :allow)");
    }

    // --- ArgMatcher::Cond tests with fallback (lines 566) ---

    #[test]
    fn arg_matcher_cond_to_doc_full() {
        let m = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)]),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            }],
            fallback: Some(Effect {
                decision: Decision::Deny,
                reason: Some("fallback".into()),
            }),
        });
        assert_eq!(
            doc_text(&m.to_doc()),
            "(cond ((positional *) (effect :allow)) (else (effect :deny \"fallback\")))"
        );
    }

    // --- ArgMatcher::to_doc When/Unless/If with branches (lines 589) ---

    #[test]
    fn arg_matcher_to_doc_when_with_branch() {
        let m = ArgMatcher::When(PolymorphicCondArm {
            branches: vec![PolymorphicCondBranch {
                predicate: MatcherCondPredicate::Expr(Expr::Literal("test".into())),
                effect: Effect {
                    decision: Decision::Allow,
                    reason: None,
                },
            }],
            fallback: None,
        });
        assert_eq!(doc_text(&m.to_doc()), "(when (\"test\" (effect :allow)))");
    }

    #[test]
    fn arg_matcher_to_doc_unless_with_branch() {
        let m = ArgMatcher::Unless(PolymorphicCondArm {
            branches: vec![PolymorphicCondBranch {
                predicate: MatcherCondPredicate::BoolExpr(BoolExpr::Has(FactQuery::Presence {
                    key: ":test".into(),
                    vector_syntax: false,
                })),
                effect: Effect {
                    decision: Decision::Deny,
                    reason: None,
                },
            }],
            fallback: None,
        });
        assert_eq!(
            doc_text(&m.to_doc()),
            "(unless ((has :test) (effect :deny)))"
        );
    }

    #[test]
    fn arg_matcher_to_doc_if_with_else() {
        let m = ArgMatcher::If {
            test: Box::new(MatcherCondPredicate::Expr(Expr::Wildcard)),
            then_effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
            else_effect: Some(Effect {
                decision: Decision::Ask,
                reason: Some("confirm".into()),
            }),
        };
        assert_eq!(
            doc_text(&m.to_doc()),
            "(if * (effect :allow) (effect :ask \"confirm\"))"
        );
    }

    // --- PolymorphicCondBranch and PolymorphicCondArm tests ---

    #[test]
    fn polymorphic_cond_branch_fields() {
        let branch = PolymorphicCondBranch {
            predicate: MatcherCondPredicate::Expr(Expr::Wildcard),
            effect: Effect {
                decision: Decision::Allow,
                reason: None,
            },
        };
        assert!(matches!(
            branch.predicate,
            MatcherCondPredicate::Expr(Expr::Wildcard)
        ));
    }

    // --- PositionalArg tests ---

    #[test]
    fn positional_arg_with_quantifier_optional() {
        let arg = PositionalArg::with_quantifier(Expr::Wildcard, Quantifier::Optional);
        assert!(matches!(arg.quantifier, Quantifier::Optional));
        assert!(!arg.recursive);
    }

    #[test]
    fn positional_arg_with_quantifier_one_or_more() {
        let arg = PositionalArg::with_quantifier(Expr::Literal("x".into()), Quantifier::OneOrMore);
        assert!(matches!(arg.quantifier, Quantifier::OneOrMore));
    }

    #[test]
    fn positional_arg_with_quantifier_zero_or_more() {
        let arg = PositionalArg::with_quantifier(Expr::Wildcard, Quantifier::ZeroOrMore);
        assert!(matches!(arg.quantifier, Quantifier::ZeroOrMore));
    }

    // --- Wrapper tests ---

    #[test]
    fn wrapper_fields() {
        let w = Wrapper {
            command: "sudo".into(),
            steps: vec![WrapperStep::Positional {
                patterns: vec![],
                capture: true,
            }],
        };
        assert_eq!(w.command, "sudo");
        assert_eq!(w.steps.len(), 1);
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
                        Expr::Bind { expr, .. } => expr.is_match(&s),
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

    // --- Property tests for quote_string escaping (lines 111-126) ---

    proptest! {
        #[test]
        fn quote_string_escapes_backslash(s in "[a-z]{0,10}") {
            let with_backslash = format!("{}\\{}", s, s);
            let quoted = quote_string(&with_backslash);
            // Backslashes should be escaped as \\
            let escaped_count = quoted.matches("\\\\").count();
            prop_assert_eq!(escaped_count, 1);
        }

        #[test]
        fn quote_string_escapes_double_quote(s in "[a-z\"]{0,20}") {
            let quoted = quote_string(&s);
            // Result should be surrounded by quotes
            prop_assert!(quoted.starts_with('"'));
            prop_assert!(quoted.ends_with('"'));
            // Any double quote should be escaped as \"
            let escaped_count = quoted.matches("\\\"").count();
            let original_quote_count = s.matches('"').count();
            prop_assert_eq!(escaped_count, original_quote_count);
        }

        #[test]
        fn quote_string_escapes_newline(s in "[a-z]{0,10}") {
            let with_newline = format!("{}\n{}", s, s);
            let quoted = quote_string(&with_newline);
            // Newlines should be escaped as \n
            let escaped_count = quoted.matches("\\n").count();
            prop_assert_eq!(escaped_count, 1);
        }

        #[test]
        fn quote_string_escapes_carriage_return(s in "[a-z]{0,10}") {
            let with_cr = format!("{}\r{}", s, s);
            let quoted = quote_string(&with_cr);
            // Carriage returns should be escaped as \r
            let escaped_count = quoted.matches("\\r").count();
            prop_assert_eq!(escaped_count, 1);
        }

        #[test]
        fn quote_string_escapes_tab(s in "[a-z]{0,10}") {
            let with_tab = format!("{}\t{}", s, s);
            let quoted = quote_string(&with_tab);
            // Tabs should be escaped as \t
            let escaped_count = quoted.matches("\\t").count();
            prop_assert_eq!(escaped_count, 1);
        }

        #[test]
        fn quote_string_is_reversible_for_safe_strings(s in "[a-zA-Z0-9_-]{0,30}") {
            let quoted = quote_string(&s);
            // For strings without special chars, we can verify structure
            prop_assert!(quoted.starts_with('"'));
            prop_assert!(quoted.ends_with('"'));
            let inner = &quoted[1..quoted.len()-1];
            prop_assert_eq!(inner, s);
        }
    }

    // --- Unit tests for has_expr_effect (lines 1062-1064) ---

    #[test]
    fn has_expr_effect_cond_returns_true() {
        let e = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("test".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        assert!(has_expr_effect(&e));
    }

    #[test]
    fn has_expr_effect_not_with_cond_returns_true() {
        let e = Expr::Not(Box::new(Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("test".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }])));
        assert!(has_expr_effect(&e));
    }

    #[test]
    fn has_expr_effect_bind_with_cond_returns_true() {
        let e = Expr::Bind {
            key: Keyword::new_unchecked(":test"),
            expr: Box::new(Expr::Cond(vec![])),
        };
        assert!(has_expr_effect(&e));
    }

    #[test]
    fn has_expr_effect_deeply_nested_returns_true() {
        let e = Expr::And(vec![
            Expr::Or(vec![
                Expr::Not(Box::new(Expr::Bind {
                    key: Keyword::new_unchecked(":deep"),
                    expr: Box::new(Expr::Cond(vec![ExprBranch {
                        test: Expr::Literal("test".into()),
                        effect: Effect { decision: Decision::Allow, reason: None },
                    }])),
                })),
            ]),
        ]);
        assert!(has_expr_effect(&e));
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
        // Doc should be an atom with value ":env"
        match &doc.node {
            crate::doc::DocF::Atom(s) => assert_eq!(s, ":env"),
            _ => panic!("expected DocF::Atom"),
        }
    }

    // --- Tests for Expr::Bind with Keyword ---

    #[test]
    fn expr_bind_with_keyword() {
        use crate::types::Expr;

        // Create a Bind expression with a Keyword
        let kw = Keyword::new(":ssh/host").unwrap();
        let bind_expr: Expr<Effect> = Expr::Bind {
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

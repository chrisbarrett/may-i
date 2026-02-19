// Shared domain types for authorization rules and configuration.

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
    /// True if this expression (or any sub-expression) is a Cond with effects.
    pub fn has_effect(&self) -> bool {
        match self {
            Expr::Cond(_) => true,
            Expr::And(exprs) | Expr::Or(exprs) => exprs.iter().any(|e| e.has_effect()),
            Expr::Not(expr) => expr.has_effect(),
            Expr::Literal(_) | Expr::Regex(_) | Expr::Wildcard => false,
        }
    }

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

/// Top-level configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wrappers: Vec<Wrapper>,
    pub security: SecurityConfig,
}

/// Security section of config.
#[derive(Clone, Default)]
pub struct SecurityConfig {
    pub blocked_paths: Vec<regex::Regex>,
    pub safe_env_vars: std::collections::HashSet<String>,
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let patterns: Vec<&str> = self.blocked_paths.iter().map(|r| r.as_str()).collect();
        f.debug_struct("SecurityConfig")
            .field("blocked_paths", &patterns)
            .field("safe_env_vars", &self.safe_env_vars)
            .finish()
    }
}

/// The blocked-path patterns that ship with the example/starter config.
/// Exposed for tests that need to exercise security filtering without
/// loading a config file.
#[cfg(test)]
pub fn default_blocked_path_patterns() -> Vec<regex::Regex> {
    [
        r"(^|/)\.env($|[./])",
        r"(^|/)\.ssh/",
        r"(^|/)\.aws/",
        r"(^|/)\.gnupg/",
        r"(^|/)\.docker/",
        r"(^|/)\.kube/",
        r"(^|/)credentials\.json($|[./])",
        r"(^|/)\.netrc($|[./])",
        r"(^|/)\.npmrc($|[./])",
        r"(^|/)\.pypirc($|[./])",
    ]
    .iter()
    .map(|p| regex::Regex::new(p).expect("invalid blocked path regex"))
    .collect()
}

/// A configured authorization rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub command: CommandMatcher,
    pub matcher: Option<ArgMatcher>,
    pub effect: Option<Effect>,
    pub checks: Vec<Check>,
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
                pexprs.iter().any(|pe| pe.expr().has_effect())
            }
            ArgMatcher::Anywhere(exprs) => exprs.iter().any(|e| e.has_effect()),
            ArgMatcher::And(matchers) | ArgMatcher::Or(matchers) => {
                matchers.iter().any(|m| m.has_effect())
            }
            ArgMatcher::Not(inner) => inner.has_effect(),
            ArgMatcher::Cond(branches) => branches.iter().any(|b| {
                b.matcher.as_ref().is_some_and(|m| m.has_effect())
            }),
        }
    }

    /// Walk the matcher tree and extract the effect from the first Expr::Cond
    /// whose branch matches. `args` are the expanded argument list.
    pub fn find_expr_effect(&self, args: &[String]) -> Option<Effect> {
        match self {
            ArgMatcher::Positional(pexprs) => {
                find_pos_expr_effect(pexprs, args, false)
            }
            ArgMatcher::ExactPositional(pexprs) => {
                find_pos_expr_effect(pexprs, args, true)
            }
            ArgMatcher::Anywhere(exprs) => {
                exprs.iter().find_map(|expr| {
                    args.iter().find_map(|arg| expr.find_effect(arg)).cloned()
                })
            }
            ArgMatcher::And(matchers) | ArgMatcher::Or(matchers) => {
                matchers.iter().find_map(|m| m.find_expr_effect(args))
            }
            ArgMatcher::Not(inner) => inner.find_expr_effect(args),
            ArgMatcher::Cond(branches) => {
                branches.iter().find_map(|b| {
                    b.matcher.as_ref().and_then(|m| m.find_expr_effect(args))
                })
            }
        }
    }
}

/// Extract positional args from an argument list, skipping flags and their values.
fn extract_positional_args(args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut flags_done = false;
    for arg in args {
        if flags_done {
            positional.push(arg.clone());
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            positional.push(arg.clone());
            flags_done = true;
            continue;
        }
        if arg.starts_with("--") {
            if !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            continue;
        }
        positional.push(arg.clone());
    }
    positional
}

/// Walk PosExpr patterns with two-cursor logic and find the first Expr::Cond effect.
fn find_pos_expr_effect(pexprs: &[PosExpr], args: &[String], exact: bool) -> Option<Effect> {
    let positional = extract_positional_args(args);
    let mut pos = 0;

    for pexpr in pexprs {
        match pexpr {
            PosExpr::One(e) => {
                if let Some(arg) = positional.get(pos) {
                    if let Some(eff) = e.find_effect(arg) {
                        return Some(eff.clone());
                    }
                    pos += 1;
                } else {
                    return None;
                }
            }
            PosExpr::Optional(e) => {
                if let Some(arg) = positional.get(pos)
                    && e.is_match(arg)
                {
                    if let Some(eff) = e.find_effect(arg) {
                        return Some(eff.clone());
                    }
                    pos += 1;
                }
            }
            PosExpr::OneOrMore(e) => {
                if positional.get(pos).is_none_or(|arg| !e.is_match(arg)) {
                    return None;
                }
                while let Some(arg) = positional.get(pos) {
                    if !e.is_match(arg) {
                        break;
                    }
                    if let Some(eff) = e.find_effect(arg) {
                        return Some(eff.clone());
                    }
                    pos += 1;
                }
            }
            PosExpr::ZeroOrMore(e) => {
                while let Some(arg) = positional.get(pos) {
                    if !e.is_match(arg) {
                        break;
                    }
                    if let Some(eff) = e.find_effect(arg) {
                        return Some(eff.clone());
                    }
                    pos += 1;
                }
            }
        }
    }

    if exact && pos != positional.len() {
        return None;
    }

    None
}

/// Wrapper configuration for command unwrapping.
#[derive(Debug, Clone)]
pub struct Wrapper {
    pub command: String,
    pub positional_args: Vec<Expr>,
    pub kind: WrapperKind,
}

#[derive(Debug, Clone)]
pub enum WrapperKind {
    /// Inner command starts after all flags (e.g., nohup, env).
    AfterFlags,
    /// Inner command starts after a specific delimiter (e.g., mise exec --).
    AfterDelimiter(String),
}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
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
        assert!(sc.blocked_paths.is_empty());
        assert!(sc.safe_env_vars.is_empty());
    }

    #[test]
    fn default_blocked_path_patterns_has_expected_paths() {
        let patterns = default_blocked_path_patterns();
        let strs: Vec<&str> = patterns.iter().map(|r| r.as_str()).collect();
        assert!(strs.iter().any(|p| p.contains(".env")));
        assert!(strs.iter().any(|p| p.contains(".ssh")));
        assert!(strs.iter().any(|p| p.contains(".aws")));
        assert!(strs.iter().any(|p| p.contains(".gnupg")));
        assert!(strs.iter().any(|p| p.contains(".docker")));
        assert!(strs.iter().any(|p| p.contains(".kube")));
        assert!(strs.iter().any(|p| p.contains("credentials")));
        assert!(strs.iter().any(|p| p.contains(".netrc")));
        assert!(strs.iter().any(|p| p.contains(".npmrc")));
        assert!(strs.iter().any(|p| p.contains(".pypirc")));
        assert_eq!(patterns.len(), 10);
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

    // --- find_pos_expr_effect with quantifiers ---

    #[test]
    fn find_expr_effect_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![
            ExprBranch {
                test: Expr::Literal("safe".into()),
                effect: Effect { decision: Decision::Allow, reason: Some("safe".into()) },
            },
            ExprBranch {
                test: Expr::Wildcard,
                effect: Effect { decision: Decision::Deny, reason: Some("bad".into()) },
            },
        ]);
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("cmd".into())),
            PosExpr::One(cond_expr),
        ]);
        let args = vec!["cmd".to_string(), "safe".to_string()];
        let eff = matcher.find_expr_effect(&args).unwrap();
        assert_eq!(eff.decision, Decision::Allow);

        let args2 = vec!["cmd".to_string(), "other".to_string()];
        let eff2 = matcher.find_expr_effect(&args2).unwrap();
        assert_eq!(eff2.decision, Decision::Deny);
    }

    #[test]
    fn find_expr_effect_exact_positional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Ask, reason: None },
        }]);
        let matcher = ArgMatcher::ExactPositional(vec![PosExpr::One(cond_expr)]);
        let eff = matcher.find_expr_effect(&["x".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Ask);

        // Too few args returns None (pattern expects 1 but 0 given)
        assert!(matcher.find_expr_effect(&[]).is_none());
    }

    #[test]
    fn find_expr_effect_optional_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("hit".into()),
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let matcher = ArgMatcher::Positional(vec![PosExpr::Optional(cond_expr)]);

        // Matches and returns effect
        let eff = matcher.find_expr_effect(&["hit".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Deny);

        // No args — optional is skipped, no effect
        assert!(matcher.find_expr_effect(&[]).is_none());
    }

    #[test]
    fn find_expr_effect_one_or_more_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let matcher = ArgMatcher::Positional(vec![PosExpr::OneOrMore(cond_expr)]);

        let eff = matcher.find_expr_effect(&["a".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Allow);

        // No args — OneOrMore fails
        assert!(matcher.find_expr_effect(&[]).is_none());
    }

    #[test]
    fn find_expr_effect_zero_or_more_with_cond() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("match".into()),
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let matcher = ArgMatcher::Positional(vec![PosExpr::ZeroOrMore(cond_expr)]);

        let eff = matcher.find_expr_effect(&["match".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Deny);

        // No matching args — zero consumed, no effect
        assert!(matcher.find_expr_effect(&[]).is_none());
    }

    #[test]
    fn find_expr_effect_too_few_args_for_one() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("a".into())),
            PosExpr::One(Expr::Literal("b".into())),
        ]);
        // Only one arg — second One fails
        assert!(matcher.find_expr_effect(&["a".to_string()]).is_none());
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

    // --- find_expr_effect through And/Or/Not/Cond ArgMatcher ---

    #[test]
    fn find_expr_effect_through_and_matcher() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]),
        ]);
        let eff = m.find_expr_effect(&["x".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Allow);
    }

    #[test]
    fn find_expr_effect_through_or_matcher() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let m = ArgMatcher::Or(vec![
            ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]),
        ]);
        let eff = m.find_expr_effect(&["x".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Deny);
    }

    #[test]
    fn find_expr_effect_through_not_matcher() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Ask, reason: None },
        }]);
        let m = ArgMatcher::Not(Box::new(
            ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]),
        ));
        let eff = m.find_expr_effect(&["x".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Ask);
    }

    #[test]
    fn find_expr_effect_through_cond_matcher() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Cond(vec![CondBranch {
            matcher: Some(ArgMatcher::Positional(vec![PosExpr::One(cond_expr)])),
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let eff = m.find_expr_effect(&["x".to_string()]).unwrap();
        assert_eq!(eff.decision, Decision::Allow);
    }

    // --- extract_positional_args in types.rs (exercised via find_pos_expr_effect) ---

    #[test]
    fn find_expr_effect_skips_flags() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("val".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]);
        // --flag consumes next arg, so "val" at index 2 is the first positional
        let eff = m.find_expr_effect(&["--flag".to_string(), "flagval".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn find_expr_effect_skips_short_flags() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("val".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]);
        let eff = m.find_expr_effect(&["-v".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn find_expr_effect_double_dash_terminates_flags() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("--".into()),
            effect: Effect { decision: Decision::Ask, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]);
        let eff = m.find_expr_effect(&["--".to_string(), "--force".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Ask);
    }

    #[test]
    fn find_expr_effect_long_flag_with_equals() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("val".into()),
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![PosExpr::One(cond_expr)]);
        // --key=value doesn't consume next arg
        let eff = m.find_expr_effect(&["--key=value".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Allow);
    }

    // --- find_pos_expr_effect: quantifier advance-without-effect paths ---

    #[test]
    fn find_pos_expr_effect_optional_advances_no_effect() {
        // Optional matches but has no effect; next pattern has the effect
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![
            PosExpr::Optional(Expr::Literal("opt".into())),
            PosExpr::One(cond_expr),
        ]);
        let eff = m.find_expr_effect(&["opt".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn find_pos_expr_effect_one_or_more_advances_no_effect() {
        // OneOrMore consumes multiple non-effect args, then next has effect
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![
            PosExpr::OneOrMore(Expr::Regex(regex::Regex::new("^f").unwrap())),
            PosExpr::One(cond_expr),
        ]);
        let eff = m.find_expr_effect(&["foo".to_string(), "far".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn find_pos_expr_effect_one_or_more_breaks_on_mismatch() {
        // OneOrMore stops when an arg doesn't match, remaining handled by next pattern
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("stop".into()),
            effect: Effect { decision: Decision::Ask, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![
            PosExpr::OneOrMore(Expr::Literal("go".into())),
            PosExpr::One(cond_expr),
        ]);
        let eff = m.find_expr_effect(&["go".to_string(), "stop".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Ask);
    }

    #[test]
    fn find_pos_expr_effect_zero_or_more_advances_no_effect() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Wildcard,
            effect: Effect { decision: Decision::Allow, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![
            PosExpr::ZeroOrMore(Expr::Literal("x".into())),
            PosExpr::One(cond_expr),
        ]);
        let eff = m.find_expr_effect(&["x".to_string(), "x".to_string(), "val".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn find_pos_expr_effect_zero_or_more_breaks_on_mismatch() {
        let cond_expr = Expr::Cond(vec![ExprBranch {
            test: Expr::Literal("end".into()),
            effect: Effect { decision: Decision::Deny, reason: None },
        }]);
        let m = ArgMatcher::Positional(vec![
            PosExpr::ZeroOrMore(Expr::Literal("a".into())),
            PosExpr::One(cond_expr),
        ]);
        // ZeroOrMore("a") consumes nothing since first arg isn't "a"
        let eff = m.find_expr_effect(&["end".to_string()]);
        assert_eq!(eff.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn find_pos_expr_effect_exact_rejects_extra() {
        // Exact mode: after consuming all patterns, extra args → None
        let m = ArgMatcher::ExactPositional(vec![
            PosExpr::One(Expr::Literal("a".into())),
        ]);
        // No effect to find, and exact check passes (1 pattern, 1 arg) → None
        assert!(m.find_expr_effect(&["a".to_string()]).is_none());
        // Extra args with exact → still None (no effects anyway)
        assert!(m.find_expr_effect(&["a".to_string(), "b".to_string()]).is_none());
    }
}

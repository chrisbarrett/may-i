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
#[derive(Clone)]
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

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            safe_env_vars: std::collections::HashSet::new(),
            blocked_paths: [
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
            .map(|p| regex::Regex::new(p).expect("invalid default blocked path regex"))
            .collect(),
        }
    }
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

/// Argument matching strategies.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    /// Match positional args by position (skip flags). Wildcard = any value.
    Positional(Vec<Expr>),
    /// Like `Positional`, but requires exactly as many positional args as patterns.
    ExactPositional(Vec<Expr>),
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
            ArgMatcher::Positional(exprs)
            | ArgMatcher::ExactPositional(exprs)
            | ArgMatcher::Anywhere(exprs) => exprs.iter().any(|e| e.has_effect()),
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
            ArgMatcher::Positional(exprs) => {
                let positional = extract_positional_args(args);
                exprs.iter().enumerate().find_map(|(i, expr)| {
                    positional.get(i).and_then(|arg| expr.find_effect(arg)).cloned()
                })
            }
            ArgMatcher::ExactPositional(exprs) => {
                let positional = extract_positional_args(args);
                if exprs.len() != positional.len() {
                    return None;
                }
                exprs.iter().enumerate().find_map(|(i, expr)| {
                    positional.get(i).and_then(|arg| expr.find_effect(arg)).cloned()
                })
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
    fn security_config_default_has_expected_paths() {
        let sc = SecurityConfig::default();
        let patterns: Vec<&str> = sc.blocked_paths.iter().map(|r| r.as_str()).collect();
        assert!(patterns.iter().any(|p| p.contains(".env")));
        assert!(patterns.iter().any(|p| p.contains(".ssh")));
        assert!(patterns.iter().any(|p| p.contains(".aws")));
        assert!(patterns.iter().any(|p| p.contains(".gnupg")));
        assert!(patterns.iter().any(|p| p.contains(".docker")));
        assert!(patterns.iter().any(|p| p.contains(".kube")));
        assert!(patterns.iter().any(|p| p.contains("credentials")));
        assert!(patterns.iter().any(|p| p.contains(".netrc")));
        assert!(patterns.iter().any(|p| p.contains(".npmrc")));
        assert!(patterns.iter().any(|p| p.contains(".pypirc")));
        assert_eq!(sc.blocked_paths.len(), 10);
    }

    #[test]
    fn security_config_default_blocks_dotenv() {
        let sc = SecurityConfig::default();
        let env_re = sc.blocked_paths.iter().find(|r| r.as_str().contains(".env")).unwrap();
        assert!(env_re.is_match(".env"));
        assert!(env_re.is_match("path/.env"));
        assert!(env_re.is_match(".env.local"));
    }

    // --- SecurityConfig::Debug ---

    #[test]
    fn security_config_debug() {
        let sc = SecurityConfig::default();
        let dbg = format!("{:?}", sc);
        assert!(dbg.contains("SecurityConfig"));
        assert!(dbg.contains(".env"));
    }
}

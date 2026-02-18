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

/// A pattern that can be either a literal string or a compiled regex.
#[derive(Clone)]
pub enum Pattern {
    Literal(String),
    Regex(regex::Regex),
}

impl Pattern {
    /// Create a pattern from a string. Strings starting with '^' are compiled as regex.
    pub fn new(s: &str) -> Result<Self, regex::Error> {
        if s.starts_with('^') {
            Ok(Pattern::Regex(regex::Regex::new(s)?))
        } else {
            Ok(Pattern::Literal(s.to_string()))
        }
    }

    /// Check if the pattern matches the given text.
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Pattern::Literal(s) => text == s,
            Pattern::Regex(re) => re.is_match(text),
        }
    }

    /// Returns true if this is the wildcard pattern "*".
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Pattern::Literal(s) if s == "*")
    }
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Literal(s) => f.debug_tuple("Literal").field(s).finish(),
            Pattern::Regex(re) => f.debug_tuple("Regex").field(&re.as_str()).finish(),
        }
    }
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
    pub decision: Option<Decision>,
    pub reason: Option<String>,
    pub examples: Vec<Example>,
}

/// A single branch inside a `cond` form.
#[derive(Debug, Clone)]
pub struct CondBranch {
    /// None means wildcard (`_` or `t`).
    pub matcher: Option<ArgMatcher>,
    pub decision: Decision,
    pub reason: Option<String>,
}

/// Argument matching strategies.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    /// Match positional args by position (skip flags). "*" = any value.
    Positional(Vec<Pattern>),
    /// Like `Positional`, but requires exactly as many positional args as patterns.
    ExactPositional(Vec<Pattern>),
    /// Token appears anywhere in argv.
    Anywhere(Vec<Pattern>),
    /// All sub-matchers must match.
    And(Vec<ArgMatcher>),
    /// Any sub-matcher must match.
    Or(Vec<ArgMatcher>),
    /// Inverts a sub-matcher.
    Not(Box<ArgMatcher>),
    /// Branch on args; first matching branch wins.
    Cond(Vec<CondBranch>),
}

/// Wrapper configuration for command unwrapping.
#[derive(Debug, Clone)]
pub struct Wrapper {
    pub command: String,
    pub positional_args: Vec<Pattern>,
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

/// An embedded example for config validation.
#[derive(Debug, Clone)]
pub struct Example {
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

    // --- Pattern::new ---

    #[test]
    fn pattern_new_literal() {
        let p = Pattern::new("hello").unwrap();
        assert!(matches!(p, Pattern::Literal(s) if s == "hello"));
    }

    #[test]
    fn pattern_new_regex() {
        let p = Pattern::new("^foo.*bar$").unwrap();
        assert!(matches!(p, Pattern::Regex(_)));
    }

    #[test]
    fn pattern_new_invalid_regex() {
        let result = Pattern::new("^[invalid");
        assert!(result.is_err());
    }

    // --- Pattern::is_match ---

    #[test]
    fn pattern_literal_exact_match() {
        let p = Pattern::new("hello").unwrap();
        assert!(p.is_match("hello"));
    }

    #[test]
    fn pattern_literal_no_match() {
        let p = Pattern::new("hello").unwrap();
        assert!(!p.is_match("world"));
    }

    #[test]
    fn pattern_literal_no_partial_match() {
        let p = Pattern::new("hello").unwrap();
        assert!(!p.is_match("hello world"));
    }

    #[test]
    fn pattern_regex_match() {
        let p = Pattern::new("^foo.*bar$").unwrap();
        assert!(p.is_match("fooXbar"));
    }

    #[test]
    fn pattern_regex_no_match() {
        let p = Pattern::new("^foo.*bar$").unwrap();
        assert!(!p.is_match("baz"));
    }

    // --- Pattern::is_wildcard ---

    #[test]
    fn pattern_is_wildcard_star() {
        let p = Pattern::new("*").unwrap();
        assert!(p.is_wildcard());
    }

    #[test]
    fn pattern_is_wildcard_not_star() {
        let p = Pattern::new("hello").unwrap();
        assert!(!p.is_wildcard());
    }

    #[test]
    fn pattern_is_wildcard_regex_not_wildcard() {
        let p = Pattern::new("^.*$").unwrap();
        assert!(!p.is_wildcard());
    }

    // --- Pattern::Debug ---

    #[test]
    fn pattern_debug_literal() {
        let p = Pattern::new("hello").unwrap();
        assert_eq!(format!("{:?}", p), r#"Literal("hello")"#);
    }

    #[test]
    fn pattern_debug_regex() {
        let p = Pattern::new("^foo$").unwrap();
        assert_eq!(format!("{:?}", p), r#"Regex("^foo$")"#);
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

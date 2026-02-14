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

impl From<&str> for Pattern {
    fn from(s: &str) -> Self {
        Pattern::new(s).expect("invalid regex pattern")
    }
}

impl From<String> for Pattern {
    fn from(s: String) -> Self {
        Pattern::from(s.as_str())
    }
}

/// Top-level configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wrappers: Vec<Wrapper>,
    pub security: SecurityConfig,
}

/// Security section of config.
#[derive(Clone)]
pub struct SecurityConfig {
    pub blocked_paths: Vec<regex::Regex>,
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let patterns: Vec<&str> = self.blocked_paths.iter().map(|r| r.as_str()).collect();
        f.debug_struct("SecurityConfig")
            .field("blocked_paths", &patterns)
            .finish()
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            blocked_paths: [
                r"\.env",
                r"\.ssh/",
                r"\.aws/",
                r"\.gnupg/",
                r"\.docker/",
                r"\.kube/",
                r"credentials\.json",
                r"\.netrc",
                r"\.npmrc",
                r"\.pypirc",
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
    pub matchers: Vec<ArgMatcher>,
    pub decision: Decision,
    pub reason: Option<String>,
    pub examples: Vec<Example>,
}

/// Argument matching strategies.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    /// Match positional args by position (skip flags). "*" = any value.
    Positional(Vec<Pattern>),
    /// Token appears anywhere in argv.
    Anywhere(Vec<Pattern>),
    /// Rule matches only if these patterns are NOT found.
    Forbidden(Vec<String>),
}

/// Wrapper configuration for command unwrapping.
#[derive(Debug, Clone)]
pub struct Wrapper {
    pub command: String,
    pub positional_args: Vec<String>,
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

impl From<&str> for CommandMatcher {
    fn from(s: &str) -> Self {
        CommandMatcher::Exact(s.to_string())
    }
}

impl From<Vec<&str>> for CommandMatcher {
    fn from(v: Vec<&str>) -> Self {
        CommandMatcher::List(v.into_iter().map(|s| s.to_string()).collect())
    }
}

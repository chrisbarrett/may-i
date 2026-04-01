// Fact-based predicate types for matching and querying.

use crate::doc::Doc;

/// Quote a string for use in source representation.
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

/// A pattern for matching fact values.
#[derive(Clone)]
pub enum FactPattern {
    /// Exact literal match.
    Literal(String),
    /// Matches any value.
    Wildcard,
    /// Regex pattern match.
    Regex(regex::Regex),
    /// All patterns must match.
    And(Vec<FactPattern>),
    /// Any pattern must match.
    Or(Vec<FactPattern>),
    /// Pattern must not match.
    Not(Box<FactPattern>),
}

impl FactPattern {
    pub(crate) fn to_doc(&self) -> Doc {
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

    #[cfg(any(test, feature = "test-generators"))]
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

/// A query against the context facts.
#[derive(Debug, Clone)]
pub enum FactQuery {
    /// Check if a key is present.
    Presence { key: String, vector_syntax: bool },
    /// Check if a key's value matches a pattern.
    Value { key: String, pattern: FactPattern },
}

impl FactQuery {
    #[cfg(test)]
    pub(crate) fn key(&self) -> &str {
        match self {
            FactQuery::Presence { key, .. } | FactQuery::Value { key, .. } => key,
        }
    }

    /// Convert to a Doc representation.
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

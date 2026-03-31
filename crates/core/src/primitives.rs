// Primitive shared types used across the codebase.

use crate::doc::Doc;

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

/// The three possible authorization decisions.
/// Ordered from least to most restrictive: Allow < Ask < Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
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

/// Trait for types that can be converted to a Doc representation.
pub trait ToDoc {
    fn to_doc(&self) -> Doc;
}

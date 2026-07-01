// Runtime context types for evaluation.

use std::collections::{BTreeMap, BTreeSet};

use crate::Keyword;

/// Runtime context containing facts used during rule evaluation.
/// All facts are stored as sets: presence facts have empty sets,
/// scalar facts have singleton sets, and multi-valued facts have multiple members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextFacts {
    values: BTreeMap<Keyword, BTreeSet<String>>,
}

impl ContextFacts {
    /// Check if a key exists in the context.
    pub fn has(&self, key: &Keyword) -> bool {
        self.values.contains_key(key)
    }

    /// True if no facts are recorded.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get the set of values for a key.
    pub fn get(&self, key: &Keyword) -> Option<&BTreeSet<String>> {
        self.values.get(key)
    }

    /// Check if a key contains a specific value.
    pub fn contains(&self, key: &Keyword, value: &str) -> bool {
        self.values.get(key).is_some_and(|set| set.contains(value))
    }

    /// Insert a presence fact (key exists with empty set).
    pub fn insert_present(&mut self, key: Keyword) {
        self.values.entry(key).or_default();
    }

    /// Insert a scalar value for a key (singleton set).
    pub fn insert_scalar(&mut self, key: Keyword, value: impl Into<String>) {
        self.values.entry(key).or_default().insert(value.into());
    }

    /// Get the scalar value for a key, if it exists and has exactly one member.
    pub fn get_scalar(&self, key: &Keyword) -> Option<&str> {
        match self.values.get(key) {
            Some(set) if set.len() == 1 => set.iter().next().map(|s| s.as_str()),
            _ => None,
        }
    }

    /// Merge another context into this one, unioning sets for shared keys.
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        for (key, other_set) in &other.values {
            merged
                .values
                .entry(key.clone())
                .or_default()
                .extend(other_set.iter().cloned());
        }
        merged
    }

    /// Iterate over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Keyword, &BTreeSet<String>)> {
        self.values.iter()
    }
}

/// A names-only, immutable snapshot of the exported environment observed at the
/// start of an invocation — the *entry environment*.
///
/// It records environment-variable **names only**, never values, so it can
/// never leak a secret into a trace, audit record, or error message. It is a
/// kind of runtime context — observed per invocation — but it is *not* a fact:
/// a fact is asserted policy context consulted by `(fact? …)`, whereas the
/// entry environment is observed ground truth consulted structurally by the
/// env-write floor. There is deliberately no value accessor; "present" /
/// "absent" is the only observable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryEnv {
    names: BTreeSet<String>,
}

impl EntryEnv {
    /// An empty entry environment — the hermetic default for `check` and the
    /// no-flag default for `eval`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from an iterator of names. Values are intentionally not accepted:
    /// the type carries names only.
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `name` was exported into the process at entry.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// True if no names are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Record that `name` was present at entry.
    pub fn insert(&mut self, name: impl Into<String>) {
        self.names.insert(name.into());
    }
}

#[cfg(test)]
mod entry_env_tests {
    use super::EntryEnv;

    #[test]
    fn empty_reports_absent() {
        let env = EntryEnv::empty();
        assert!(env.is_empty());
        assert!(!env.contains("PATH"));
    }

    #[test]
    fn present_name_is_observable_as_presence() {
        let env = EntryEnv::from_names(["AWS_SECRET_ACCESS_KEY", "PATH"]);
        assert!(env.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(env.contains("PATH"));
        assert!(!env.contains("LD_PRELOAD"));
        assert!(!env.is_empty());
    }

    #[test]
    fn insert_adds_a_name() {
        let mut env = EntryEnv::empty();
        env.insert("GIT_DIR");
        assert!(env.contains("GIT_DIR"));
    }

    // The names-only invariant is enforced structurally: `EntryEnv` exposes no
    // value accessor at all, so no code path can render a value from it. This
    // test documents that the only observable is presence.
    #[test]
    fn carries_names_only() {
        let env = EntryEnv::from_names(["SECRET"]);
        // Presence is observable…
        assert!(env.contains("SECRET"));
        // …and there is no API to retrieve a value (compile-time guarantee).
    }
}

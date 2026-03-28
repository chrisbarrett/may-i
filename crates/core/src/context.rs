// Runtime context types for evaluation.

use std::collections::{BTreeMap, BTreeSet};

/// Runtime context containing facts used during rule evaluation.
/// All facts are stored as sets: presence facts have empty sets,
/// scalar facts have singleton sets, and multi-valued facts have multiple members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextFacts {
    values: BTreeMap<String, BTreeSet<String>>,
}

impl ContextFacts {
    /// Check if a key exists in the context.
    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Get the set of values for a key.
    pub fn get(&self, key: &str) -> Option<&BTreeSet<String>> {
        self.values.get(key)
    }

    /// Check if a key contains a specific value.
    pub fn contains(&self, key: &str, value: &str) -> bool {
        self.values.get(key).is_some_and(|set| set.contains(value))
    }

    /// Insert a presence fact (key exists with empty set).
    pub fn insert_present(&mut self, key: impl Into<String>) {
        self.values.entry(key.into()).or_default();
    }

    /// Insert a scalar value for a key (singleton set).
    pub fn insert_scalar(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .entry(key.into())
            .or_default()
            .insert(value.into());
    }

    /// Push a value onto the set at the given key, accumulating values.
    pub fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .entry(key.into())
            .or_default()
            .insert(value.into());
    }

    /// Get the scalar value for a key, if it exists and has exactly one member.
    pub fn get_scalar(&self, key: &str) -> Option<&str> {
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
    pub fn iter(&self) -> impl Iterator<Item = (&str, &BTreeSet<String>)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }
}

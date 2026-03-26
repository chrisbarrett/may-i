// Runtime context types for evaluation.

use std::collections::BTreeMap;

/// A value stored in the context: either just present, or a scalar string value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextValue {
    /// Key exists without a value.
    Present,
    /// Key exists with a string value.
    Scalar(String),
}

/// Runtime context containing facts used during rule evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextFacts {
    values: BTreeMap<String, ContextValue>,
}

impl ContextFacts {
    /// Check if a key exists in the context.
    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Get the value for a key.
    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.values.get(key)
    }

    /// Get the scalar value for a key, if it exists and is a scalar.
    pub fn get_scalar(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(ContextValue::Scalar(value)) => Some(value.as_str()),
            Some(ContextValue::Present) | None => None,
        }
    }

    /// Insert a presence fact (key exists without value).
    pub fn insert_present(&mut self, key: impl Into<String>) {
        self.values.insert(key.into(), ContextValue::Present);
    }

    /// Insert a scalar value for a key.
    pub fn insert_scalar(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .insert(key.into(), ContextValue::Scalar(value.into()));
    }

    /// Merge another context into this one.
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.values.extend(other.values.clone());
        merged
    }

    /// Iterate over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ContextValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }
}

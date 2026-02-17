use super::ast::{ParameterOperator, WordPart};
use super::glob::{glob_replace, glob_strip_prefix, glob_strip_suffix};

/// Resolve a `ParameterExpansionOp` given an env snapshot. If the variable is in
/// env, apply the operator and return a `Literal`. Otherwise return the original part.
pub(crate) fn resolve_param_op(
    name: &str,
    op: &ParameterOperator,
    env: &std::collections::HashMap<String, String>,
) -> WordPart {
    let val = match env.get(name) {
        Some(v) => v.as_str(),
        None => {
            return WordPart::ParameterExpansionOp {
                name: name.to_string(),
                op: op.clone(),
            };
        }
    };

    let result = match op {
        ParameterOperator::Length => val.len().to_string(),
        ParameterOperator::StripPrefix { longest, pattern } => {
            glob_strip_prefix(pattern, val, *longest).to_string()
        }
        ParameterOperator::StripSuffix { longest, pattern } => {
            glob_strip_suffix(pattern, val, *longest).to_string()
        }
        ParameterOperator::Replace { all, pattern, replacement } => {
            glob_replace(pattern, val, replacement, *all)
        }
        ParameterOperator::Default { colon, value } => {
            if *colon {
                // ${VAR:-val}: use default if unset or empty
                if val.is_empty() { value.clone() } else { val.to_string() }
            } else {
                // ${VAR-val}: use default if unset (var is set, so use val)
                val.to_string()
            }
        }
        ParameterOperator::Alternative { colon, value } => {
            if *colon {
                // ${VAR:+val}: use alternative if set and non-empty
                if val.is_empty() { String::new() } else { value.clone() }
            } else {
                // ${VAR+val}: use alternative if set (var is set)
                value.clone()
            }
        }
        ParameterOperator::Error { .. } => {
            // Variable is set, so no error; resolve to the value
            val.to_string()
        }
        ParameterOperator::Assign { .. } => {
            // Variable is set, so no assignment; resolve to the value
            val.to_string()
        }
        ParameterOperator::Substring { offset, length } => {
            let off: isize = offset.trim().parse().unwrap_or(0);
            let chars: Vec<char> = val.chars().collect();
            let start = if off < 0 {
                (chars.len() as isize + off).max(0) as usize
            } else {
                (off as usize).min(chars.len())
            };
            match length {
                Some(len_str) => {
                    let len: usize = len_str.trim().parse().unwrap_or(chars.len());
                    let end = (start + len).min(chars.len());
                    chars[start..end].iter().collect()
                }
                None => chars[start..].iter().collect(),
            }
        }
        ParameterOperator::Uppercase { all } => {
            if *all {
                val.to_uppercase()
            } else {
                let mut chars = val.chars();
                match chars.next() {
                    Some(c) => c.to_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            }
        }
        ParameterOperator::Lowercase { all } => {
            if *all {
                val.to_lowercase()
            } else {
                let mut chars = val.chars();
                match chars.next() {
                    Some(c) => c.to_lowercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            }
        }
    };
    WordPart::Literal(result)
}

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
        ParameterOperator::Replace {
            all,
            pattern,
            replacement,
        } => glob_replace(pattern, val, replacement, *all),
        ParameterOperator::Default { colon, value } => {
            if *colon {
                // ${VAR:-val}: use default if unset or empty
                if val.is_empty() {
                    value.clone()
                } else {
                    val.to_string()
                }
            } else {
                // ${VAR-val}: use default if unset (var is set, so use val)
                val.to_string()
            }
        }
        ParameterOperator::Alternative { colon, value } => {
            if *colon {
                // ${VAR:+val}: use alternative if set and non-empty
                if val.is_empty() {
                    String::new()
                } else {
                    value.clone()
                }
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

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating strings
    fn arb_string() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a-zA-Z0-9_-]{0,30}").unwrap()
    }

    fn arb_nonempty_string() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a-zA-Z0-9_-]{1,30}").unwrap()
    }

    // Property 3.2: default operator with colon uses empty check
    proptest! {
        #[test]
        fn prop_default_colon_uses_empty(value in arb_string(), default_val in arb_string()) {
            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let op = ParameterOperator::Default {
                colon: true,
                value: default_val.clone(),
            };
            let result = resolve_param_op("VAR", &op, &env);

            if value.is_empty() {
                // Empty value should return default
                assert_eq!(result, WordPart::Literal(default_val));
            } else {
                // Non-empty value should return original
                assert_eq!(result, WordPart::Literal(value));
            }
        }
    }

    // Property 3.3: default operator without colon only checks unset
    proptest! {
        #[test]
        fn prop_default_no_colon_only_unset(default_val in arb_string()) {
            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), "".to_string());

            let op = ParameterOperator::Default {
                colon: false,
                value: default_val.clone(),
            };
            // Variable is set (even if empty), so should return empty value
            let result = resolve_param_op("VAR", &op, &env);
            assert_eq!(result, WordPart::Literal("".to_string()));
        }
    }

    // Property 3.4: shortest prefix strip removes minimal match
    proptest! {
        #[test]
        fn prop_strip_prefix_shortest(value in arb_nonempty_string()) {
            // Pattern that matches the first character
            let pattern = &value[0..1];
            let op = ParameterOperator::StripPrefix {
                longest: false,
                pattern: pattern.to_string(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let expected = value.strip_prefix(pattern).unwrap_or(&value);
            assert_eq!(result, WordPart::Literal(expected.to_string()));
        }
    }

    // Property 3.5: longest prefix strip removes maximal match
    proptest! {
        #[test]
        fn prop_strip_prefix_longest(value in arb_nonempty_string()) {
            // Pattern that matches all characters
            let pattern = "*";
            let op = ParameterOperator::StripPrefix {
                longest: true,
                pattern: pattern.to_string(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            // With longest=true and pattern *, entire string should be stripped
            assert_eq!(result, WordPart::Literal("".to_string()));
        }
    }

    // Property 3.6: shortest suffix strip removes minimal match
    proptest! {
        #[test]
        fn prop_strip_suffix_shortest(value in arb_nonempty_string()) {
            // Pattern that matches the last character
            let pattern = &value[value.len()-1..];
            let op = ParameterOperator::StripSuffix {
                longest: false,
                pattern: pattern.to_string(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let expected = value.strip_suffix(pattern).unwrap_or(&value);
            assert_eq!(result, WordPart::Literal(expected.to_string()));
        }
    }

    // Property 3.7: longest suffix strip removes maximal match
    proptest! {
        #[test]
        fn prop_strip_suffix_longest(value in arb_nonempty_string()) {
            // Pattern that matches all characters
            let pattern = "*";
            let op = ParameterOperator::StripSuffix {
                longest: true,
                pattern: pattern.to_string(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            // With longest=true and pattern *, entire string should be stripped
            assert_eq!(result, WordPart::Literal("".to_string()));
        }
    }

    // Property 3.8: replace first only affects first occurrence
    proptest! {
        #[test]
        fn prop_replace_first_only(value in "[a]{5,20}", replacement in arb_string()) {
            let op = ParameterOperator::Replace {
                all: false,
                pattern: "a".to_string(),
                replacement: replacement.clone(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let expected = value.replacen("a", &replacement, 1);
            assert_eq!(result, WordPart::Literal(expected));
        }
    }

    // Property 3.9: replace all affects all occurrences
    proptest! {
        #[test]
        fn prop_replace_all(value in "[a]{5,20}", replacement in arb_string()) {
            let op = ParameterOperator::Replace {
                all: true,
                pattern: "a".to_string(),
                replacement: replacement.clone(),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let expected = value.replace("a", &replacement);
            assert_eq!(result, WordPart::Literal(expected));
        }
    }

    // Property 3.10: substring with positive offset
    proptest! {
        #[test]
        fn prop_substring_positive_offset(value in arb_string()) {
            let offset = 2usize;
            let op = ParameterOperator::Substring {
                offset: offset.to_string(),
                length: None,
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let chars: Vec<char> = value.chars().collect();
            let start = offset.min(chars.len());
            let expected: String = chars[start..].iter().collect();
            assert_eq!(result, WordPart::Literal(expected));
        }
    }

    // Property 3.11: substring with negative offset counts from end
    proptest! {
        #[test]
        fn prop_substring_negative_offset(value in arb_nonempty_string()) {
            let offset = -2isize;
            let op = ParameterOperator::Substring {
                offset: offset.to_string(),
                length: None,
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let chars: Vec<char> = value.chars().collect();
            let start = (chars.len() as isize + offset).max(0) as usize;
            let expected: String = chars[start..].iter().collect();
            assert_eq!(result, WordPart::Literal(expected));
        }
    }

    // Property 3.12: substring with length limits result
    proptest! {
        #[test]
        fn prop_substring_with_length(value in arb_string()) {
            let offset = 1usize;
            let length = 3usize;
            let op = ParameterOperator::Substring {
                offset: offset.to_string(),
                length: Some(length.to_string()),
            };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            let result = resolve_param_op("VAR", &op, &env);
            let chars: Vec<char> = value.chars().collect();
            let start = offset.min(chars.len());
            let end = (start + length).min(chars.len());
            let expected: String = chars[start..end].iter().collect();
            assert_eq!(result, WordPart::Literal(expected));
        }
    }

    // Property 3.13: case conversion roundtrip for ASCII
    proptest! {
        #[test]
        fn prop_case_roundtrip(value in "[a-zA-Z]{0,30}") {
            let upper_op = ParameterOperator::Uppercase { all: true };
            let lower_op = ParameterOperator::Lowercase { all: true };

            let mut env = std::collections::HashMap::new();
            env.insert("VAR".to_string(), value.clone());

            // Upper then lower should give lowercase
            let upper_result = resolve_param_op("VAR", &upper_op, &env);
            let upper_str = match &upper_result {
                WordPart::Literal(s) => s.clone(),
                _ => panic!("Expected Literal"),
            };
            env.insert("VAR2".to_string(), upper_str);
            let lower_result = resolve_param_op("VAR2", &lower_op, &env);
            let lower_str = match &lower_result {
                WordPart::Literal(s) => s.clone(),
                _ => panic!("Expected Literal"),
            };

            // After upper then lower, should be all lowercase
            assert_eq!(lower_str, value.to_lowercase());
        }
    }
}

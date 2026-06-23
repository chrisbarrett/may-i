use super::ast::{ParameterOperator, WordPart};
use super::glob::{glob_replace, glob_strip_prefix, glob_strip_suffix};

/// Resolve a `ParameterExpansionOp` given an env snapshot. If the variable is in
/// env, apply the operator and return a `Literal`. Otherwise return the original part.
pub(crate) fn resolve_param_op(
    name: &str,
    op: &ParameterOperator,
    embedded: &[WordPart],
    env: &std::collections::HashMap<String, String>,
) -> WordPart {
    let unresolved = || WordPart::ParameterExpansionOp {
        name: name.to_string(),
        op: op.clone(),
        embedded: embedded.to_vec(),
    };

    let val = match env.get(name) {
        Some(v) => v.as_str(),
        // Unresolved: keep the operand substitutions so a later extraction
        // of the resolved word still sees them.
        None => return unresolved(),
    };

    // An operand string that bash would itself expand (a nested `$VAR`, a
    // command substitution, or — for operands that become part of the output —
    // a glob or leading tilde) would make our resolved literal diverge from the
    // string bash actually produces. Resolving such a word and clearing its
    // expansion-bearing flag could wrongly satisfy an `:allow` (it did, before
    // arguments resolved operator forms). When any operand is expandable, stay
    // unresolved so the word remains expansion-bearing and floors, matching the
    // change's all-or-nothing / when-in-doubt-stay-dynamic stance.
    if !op_operands_are_inert(op) {
        return unresolved();
    }

    let result = match op {
        // bash `${#VAR}` counts characters, not bytes.
        ParameterOperator::Length => val.chars().count().to_string(),
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

/// Whether every operand of `op` is inert — safe to resolve to a literal
/// because bash would not further expand it in a way that diverges from our
/// computed result.
///
/// Two operand roles:
/// - **pattern** (strip/replace match pattern): bash treats glob metachars as
///   pattern syntax against the value, which `glob_*` already mirrors, so they
///   are inert here; only a nested expansion (`$`/`` ` ``) would diverge.
/// - **output** (default/alternative/assign value, error message, replacement):
///   becomes part of the produced word, so bash additionally globs and tilde-
///   expands it — any glob metachar or leading tilde is *not* inert.
///
/// Substring offset/length are arithmetic operands; a nested expansion there
/// would change the numeric result, so they are checked as patterns too.
fn op_operands_are_inert(op: &ParameterOperator) -> bool {
    match op {
        ParameterOperator::Length
        | ParameterOperator::Uppercase { .. }
        | ParameterOperator::Lowercase { .. } => true,
        ParameterOperator::StripPrefix { pattern, .. }
        | ParameterOperator::StripSuffix { pattern, .. } => pattern_is_inert(pattern),
        ParameterOperator::Replace {
            all,
            pattern,
            replacement,
        } => {
            replace_pattern_is_inert(pattern)
                && output_is_inert(replacement)
                // An all-replace whose pattern matches the empty string makes no
                // progress per match in `glob_replace` (a zero-width match never
                // advances), so it must not be resolved — both to avoid the hang
                // and because bash's adjacent/trailing empty-match suppression is
                // not reproduced here. A first-only replace terminates, so it is
                // unaffected.
                && !(*all && pattern_matches_empty(pattern))
        }
        ParameterOperator::Default { value, .. }
        | ParameterOperator::Alternative { value, .. }
        | ParameterOperator::Assign { value, .. } => output_is_inert(value),
        ParameterOperator::Error { message, .. } => output_is_inert(message),
        ParameterOperator::Substring { offset, length } => {
            is_plain_integer(offset) && length.as_deref().is_none_or(is_plain_integer)
        }
    }
}

/// Whether an arithmetic operand is a plain decimal integer that our `parse`
/// interprets identically to bash. bash treats substring offset/length as full
/// *arithmetic expressions* — `2+2`, octal `010`, hex `0x10`, base `8#17`,
/// nested variables — whereas resolution does a bare `str::parse::<isize>`. Any
/// operand beyond an optionally-signed run of decimal digits would diverge (a
/// non-numeric expression silently falls back to `0`/full-length, an octal/hex
/// literal is read as decimal), so only a plain integer is inert; everything
/// else floors the word.
fn is_plain_integer(s: &str) -> bool {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    // A leading `0` on a multi-digit run is octal to bash but decimal to us, so
    // reject it too. A single `0` is unambiguous.
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !(digits.len() > 1 && digits.starts_with('0'))
}

/// A match-pattern operand is inert unless it carries a nested expansion
/// (`$VAR`, `${…}`, `$(…)`, or backtick), a brace metachar, or a backslash.
/// Glob metachars (`*?[`) are intended pattern syntax mirrored by the `glob_*`
/// helpers, so they are inert here — but braces are not pattern syntax: bash
/// performs brace expansion on the whole word *before* parameter expansion, so
/// a `{` smuggled into any operand splits the word at runtime in a way our
/// single-literal result would not reflect.
///
/// A backslash is *not* inert: in a bash match pattern `\*`/`\[` escape the
/// following metachar so it matches *literally*, but the `glob_*` helpers treat
/// `\` as an ordinary character and the metachar as still-wild. That divergence
/// makes our resolved literal differ from bash's runtime argument (`${Y#\[p\]}`
/// strips `[p]` for bash but not for us), which could dodge a deny or satisfy an
/// `:allow` on the wrong value. Rejecting any backslash keeps such words floored.
fn pattern_is_inert(s: &str) -> bool {
    !contains_expansion_sigil(s) && !contains_brace(s) && !s.contains('\\')
}

/// A replace-operator pattern (`${VAR/pat/rep}`) is inert under the same rules
/// as any match pattern, with one extra exclusion: a leading `#` or `%` is a
/// bash *anchor* (`/#` matches only at the start, `/%` only at the end). The
/// lexer captures the anchor as a literal first character of the pattern, and
/// the AST has no field to carry it, so `glob_replace` would search for the
/// literal `#`/`%` instead of anchoring — diverging from bash (`${Y/#b/}` on
/// `b/etc/shadow` yields `/etc/shadow` for bash but `b/etc/shadow` for us).
/// Floor any anchored replace so the divergence cannot satisfy or dodge policy.
fn replace_pattern_is_inert(pattern: &str) -> bool {
    !pattern.starts_with(['#', '%']) && pattern_is_inert(pattern)
}

/// Whether a glob pattern can match the empty string. Only a pattern made
/// solely of `*` quantifiers (including the empty pattern) does — any literal
/// char, `?` (one char), or `[...]` (one char) requires at least one input
/// char. Used to reject an all-replace that would loop on zero-width matches.
fn pattern_matches_empty(pattern: &str) -> bool {
    pattern.bytes().all(|b| b == b'*')
}

/// An output operand (one that becomes part of the produced word) is inert
/// only when bash would pass it through verbatim: no nested expansion, no brace
/// expansion, no glob metachar, no leading tilde, and no backslash. A backslash
/// is dropped by bash's quote removal on the operand (`${A:-a\b}` yields `ab`),
/// but our resolution keeps it verbatim, so the literals diverge.
fn output_is_inert(s: &str) -> bool {
    !contains_expansion_sigil(s)
        && !contains_brace(s)
        && !s.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
        && !s.starts_with('~')
}

/// Whether a brace-expansion metachar (`{` or `}`) appears. The lexer truncates
/// an operand at the first `}`, so a brace-expansion group smuggled into an
/// operand surfaces here as an unmatched opening `{`; rejecting either brace is
/// the conservative, when-in-doubt-stay-dynamic choice. (`{a,b}` at top level
/// is already modelled as expansion-bearing; this closes the operator-operand
/// hiding place.)
fn contains_brace(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // an escaped brace is literal
            b'{' | b'}' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Whether an unescaped `$` or backtick appears, signalling a nested parameter,
/// command, or arithmetic expansion the lexer left as verbatim operand text.
/// A backslash before the sigil escapes it (bash does not expand `\$`).
fn contains_expansion_sigil(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip the escaped byte
            b'$' | b'`' => return true,
            _ => i += 1,
        }
    }
    false
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
            let result = resolve_param_op("VAR", &op, &[], &env);

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
            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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

            let result = resolve_param_op("VAR", &op, &[], &env);
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
            let upper_result = resolve_param_op("VAR", &upper_op, &[], &env);
            let upper_str = match &upper_result {
                WordPart::Literal(s) => s.clone(),
                _ => panic!("Expected Literal"),
            };
            env.insert("VAR2".to_string(), upper_str);
            let lower_result = resolve_param_op("VAR2", &lower_op, &[], &env);
            let lower_str = match &lower_result {
                WordPart::Literal(s) => s.clone(),
                _ => panic!("Expected Literal"),
            };

            // After upper then lower, should be all lowercase
            assert_eq!(lower_str, value.to_lowercase());
        }
    }
}

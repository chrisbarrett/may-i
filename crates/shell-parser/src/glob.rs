/// Match a glob pattern against text. Supports `*`, `?`, and `[...]` character
/// classes (including negation with `!` or `^`). Returns true if the entire text
/// matches the pattern.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let (mut star_pi, mut star_ti) = (usize::MAX, usize::MAX);

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '?' {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if pi < pat.len() && pat[pi] == '[' {
            if let Some((matched, end)) = glob_match_bracket(&pat[pi..], txt[ti]) {
                if matched {
                    pi += end;
                    ti += 1;
                } else if star_pi != usize::MAX {
                    pi = star_pi + 1;
                    star_ti += 1;
                    ti = star_ti;
                } else {
                    return false;
                }
            } else {
                // Malformed bracket — treat as literal
                if pat[pi] == txt[ti] {
                    pi += 1;
                    ti += 1;
                } else if star_pi != usize::MAX {
                    pi = star_pi + 1;
                    star_ti += 1;
                    ti = star_ti;
                } else {
                    return false;
                }
            }
        } else if pi < pat.len() && pat[pi] == txt[ti] {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Try to match a bracket expression `[...]` at the start of `pat` against
/// character `ch`. Returns `Some((matched, chars_consumed))` or `None` if
/// the bracket is malformed (no closing `]`).
fn glob_match_bracket(pat: &[char], ch: char) -> Option<(bool, usize)> {
    // pat[0] == '['
    let mut i = 1;
    let negate = if i < pat.len() && (pat[i] == '!' || pat[i] == '^') {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    // A ']' immediately after '[' (or '[!' / '[^') is treated as literal
    if i < pat.len() && pat[i] == ']' {
        if ch == ']' {
            matched = true;
        }
        i += 1;
    }

    while i < pat.len() && pat[i] != ']' {
        if i + 2 < pat.len() && pat[i + 1] == '-' && pat[i + 2] != ']' {
            // Range: [a-z]
            let lo = pat[i];
            let hi = pat[i + 2];
            if ch >= lo && ch <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }

    if i < pat.len() && pat[i] == ']' {
        Some((matched ^ negate, i + 1))
    } else {
        None // no closing ]
    }
}

/// Strip the shortest or longest prefix matching `pattern` from `text`.
pub(crate) fn glob_strip_prefix<'a>(pattern: &str, text: &'a str, longest: bool) -> &'a str {
    let chars: Vec<char> = text.chars().collect();
    let mut result: Option<usize> = None;
    // Try each prefix length from 0..=len
    for i in 0..=chars.len() {
        let prefix: String = chars[..i].iter().collect();
        if glob_match(pattern, &prefix) {
            result = Some(i);
            if !longest {
                break; // shortest match found
            }
        }
    }
    match result {
        Some(n) => {
            let byte_offset: usize = chars[..n].iter().map(|c| c.len_utf8()).sum();
            &text[byte_offset..]
        }
        None => text,
    }
}

/// Strip the shortest or longest suffix matching `pattern` from `text`.
pub(crate) fn glob_strip_suffix<'a>(pattern: &str, text: &'a str, longest: bool) -> &'a str {
    let chars: Vec<char> = text.chars().collect();
    let mut result: Option<usize> = None;
    // Try each suffix starting position from len down to 0
    for i in (0..=chars.len()).rev() {
        let suffix: String = chars[i..].iter().collect();
        if glob_match(pattern, &suffix) {
            result = Some(i);
            if !longest {
                break; // shortest match found
            }
        }
    }
    match result {
        Some(n) => {
            let byte_offset: usize = chars[..n].iter().map(|c| c.len_utf8()).sum();
            &text[..byte_offset]
        }
        None => text,
    }
}

/// Find the first occurrence of `pattern` in `text` using glob matching, and
/// replace it (or all occurrences if `all` is true) with `replacement`.
pub(crate) fn glob_replace(pattern: &str, text: &str, replacement: &str, all: bool) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut result = String::new();
    let mut i = 0;

    while i <= chars.len() {
        let mut matched = false;
        // Try match lengths from longest to shortest at position i
        for j in (i..=chars.len()).rev() {
            let substr: String = chars[i..j].iter().collect();
            if glob_match(pattern, &substr) {
                result.push_str(replacement);
                i = j;
                matched = true;
                if !all {
                    // Append the rest and return
                    let rest: String = chars[i..].iter().collect();
                    result.push_str(&rest);
                    return result;
                }
                break;
            }
        }
        if !matched {
            if i < chars.len() {
                result.push(chars[i]);
            }
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Reference implementation using backtracking for comparison.
    /// This is a simpler but slower implementation to verify against.
    fn reference_backtrack_match(pattern: &str, text: &str) -> bool {
        reference_backtrack_match_inner(
            &pattern.chars().collect::<Vec<_>>(),
            &text.chars().collect::<Vec<_>>(),
        )
    }

    fn reference_backtrack_match_inner(pat: &[char], txt: &[char]) -> bool {
        match pat.first() {
            None => txt.is_empty(),
            Some(&'*') => {
                // Star matches empty or any prefix
                (0..=txt.len()).any(|i| reference_backtrack_match_inner(&pat[1..], &txt[i..]))
            }
            Some(&'?') => {
                // Question matches exactly one character
                !txt.is_empty() && reference_backtrack_match_inner(&pat[1..], &txt[1..])
            }
            Some(&'[') => {
                // Try to parse bracket expression
                if let Some((matched_len, consumes)) =
                    reference_match_bracket(pat, txt.first().copied())
                {
                    matched_len > 0 && reference_backtrack_match_inner(&pat[consumes..], &txt[1..])
                } else {
                    // Malformed bracket - treat as literal
                    !txt.is_empty()
                        && pat[0] == txt[0]
                        && reference_backtrack_match_inner(&pat[1..], &txt[1..])
                }
            }
            Some(&pc) => {
                // Literal character match
                !txt.is_empty()
                    && pc == txt[0]
                    && reference_backtrack_match_inner(&pat[1..], &txt[1..])
            }
        }
    }

    fn reference_match_bracket(pat: &[char], ch: Option<char>) -> Option<(usize, usize)> {
        let ch = ch?;
        let mut i = 1; // Skip '['
        let negate = if i < pat.len() && (pat[i] == '!' || pat[i] == '^') {
            i += 1;
            true
        } else {
            false
        };

        let mut matched = false;
        // A ']' immediately after '[' (or '[!' / '[^') is treated as literal
        if i < pat.len() && pat[i] == ']' {
            if ch == ']' {
                matched = true;
            }
            i += 1;
        }

        while i < pat.len() && pat[i] != ']' {
            if i + 2 < pat.len() && pat[i + 1] == '-' && pat[i + 2] != ']' {
                let lo = pat[i];
                let hi = pat[i + 2];
                if ch >= lo && ch <= hi {
                    matched = true;
                }
                i += 3;
            } else {
                if pat[i] == ch {
                    matched = true;
                }
                i += 1;
            }
        }

        if i < pat.len() && pat[i] == ']' {
            Some((if matched ^ negate { 1 } else { 0 }, i + 1))
        } else {
            None
        }
    }

    // Strategy for generating valid glob patterns
    fn arb_glob_pattern() -> impl Strategy<Value = String> {
        let chars = prop_oneof!(
            Just("*".to_string()),
            Just("?".to_string()),
            "[a-z]".prop_map(|s| format!("[{}]", s)),
            "[a-z]{1,3}".prop_map(|s| s.chars().collect::<String>()),
        );
        proptest::collection::vec(chars, 0..10).prop_map(|parts| parts.concat())
    }

    // Strategy for generating text to match against
    fn arb_text() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[a-zA-Z0-9]{0,20}").unwrap()
    }

    // Property 2.3: glob_match equivalence with reference implementation
    proptest! {
        #[test]
        fn prop_glob_match_equivalence(pattern in arb_glob_pattern(), text in arb_text()) {
            let expected = reference_backtrack_match(&pattern, &text);
            let actual = glob_match(&pattern, &text);
            prop_assert_eq!(
                actual, expected,
                "glob_match({:?}, {:?}) returned {} but expected {}",
                pattern, text, actual, expected
            );
        }
    }

    // Property 2.4: empty string handling for all patterns
    proptest! {
        #[test]
        fn prop_empty_string_handling(pattern in arb_glob_pattern()) {
            let result = glob_match(&pattern, "");
            // Empty string should only match if pattern is all stars or empty
            let expected = pattern.chars().all(|c| c == '*');
            prop_assert_eq!(
                result, expected,
                "Pattern {:?} matched empty string: {}",
                pattern, result
            );
        }
    }

    // Property 2.5: negation bracket is complement of positive bracket
    proptest! {
        #[test]
        fn prop_negation_is_complement(ch in "[a-z]") {
            let positive = format!("[{}]", ch);
            let negated = format!("[!{}]", ch);

            // For any character, exactly one of positive or negated should match
            for test_ch in 'a'..='z' {
                let pos_match = glob_match(&positive, &test_ch.to_string());
                let neg_match = glob_match(&negated, &test_ch.to_string());
                prop_assert_ne!(
                    pos_match, neg_match,
                    "Character {}: positive={:?}, negated={:?}",
                    test_ch, pos_match, neg_match
                );
            }
        }
    }

    // Property 2.6: strip_prefix preserves remainder (inverse operation)
    proptest! {
        #[test]
        fn prop_strip_prefix_inverse(pattern in arb_glob_pattern(), text in arb_text()) {
            let text_clone = text.clone();
            let stripped = glob_strip_prefix(&pattern, &text, false);
            let prefix_len = text.len() - stripped.len();
            let prefix = &text[..prefix_len];

            // The stripped part plus prefix should reconstruct original
            prop_assert_eq!(
                prefix.to_string() + stripped,
                text_clone,
                "strip_prefix did not preserve remainder"
            );

            // If something was stripped, the prefix should match the pattern
            if !stripped.is_empty() || prefix_len > 0 {
                prop_assert!(
                    glob_match(&pattern, prefix) || prefix.is_empty(),
                    "Stripped prefix {:?} does not match pattern {:?}",
                    prefix, pattern
                );
            }
        }
    }

    // Property 2.7: strip_suffix preserves prefix (inverse operation)
    proptest! {
        #[test]
        fn prop_strip_suffix_inverse(pattern in arb_glob_pattern(), text in arb_text()) {
            let text_len = text.len();
            let stripped = glob_strip_suffix(&pattern, &text, false);
            let suffix_start = stripped.len();
            let suffix = &text[suffix_start..];

            // The prefix plus stripped part should reconstruct original
            prop_assert_eq!(
                stripped.to_string() + suffix,
                text.clone(),
                "strip_suffix did not preserve prefix"
            );

            // If something was stripped, the suffix should match the pattern
            if !stripped.is_empty() || suffix_start < text_len {
                prop_assert!(
                    glob_match(&pattern, suffix) || suffix.is_empty(),
                    "Stripped suffix {:?} does not match pattern {:?}",
                    suffix, pattern
                );
            }
        }
    }

    // Property 2.8: replace all vs first only behavior
    proptest! {
        #[test]
        fn prop_replace_all_vs_first(
            pattern in "[a-z]{1,2}",
            text in "[a-z]{0,30}",
            replacement in "[0-9]{1,2}"
        ) {
            let first_only = glob_replace(&pattern, &text, &replacement, false);
            let all = glob_replace(&pattern, &text, &replacement, true);

            // Count occurrences of pattern in text
            let mut count = 0;
            for i in 0..text.len().saturating_sub(pattern.len() - 1) {
                if glob_match(&pattern, &text[i..i + pattern.len()]) {
                    count += 1;
                }
            }

            if count <= 1 {
                // If 0 or 1 matches, both should produce the same result
                prop_assert_eq!(
                    first_only, all,
                    "With {} matches, first_only and all should be equal",
                    count
                );
            } else {
                // With multiple matches, all should have more replacements
                let first_count = first_only.matches(&replacement).count();
                let all_count = all.matches(&replacement).count();
                prop_assert!(
                    all_count >= first_count,
                    "replace_all should have at least as many replacements as first_only"
                );
            }
        }
    }

    // Property 2.9: no-match returns original unchanged (skip empty pattern and patterns that match empty)
    proptest! {
        #[test]
        fn prop_no_match_returns_original(pattern in "[a-z]{1,5}", text in arb_text()) {
            let result = glob_replace(&pattern, &text, "XXX", false);

            // If the pattern doesn't appear in text, result should equal text
            let mut pattern_found = false;
            if pattern.len() <= text.len() {
                for i in 0..=text.len() - pattern.len() {
                    if glob_match(&pattern, &text[i..i + pattern.len()]) {
                        pattern_found = true;
                        break;
                    }
                }
            }

            if !pattern_found {
                prop_assert_eq!(
                    result, text,
                    "When pattern not found, result should equal original text"
                );
            }
        }
    }

    // Edge case: empty pattern matches empty text only
    #[test]
    fn prop_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    // Edge case: star matches everything
    #[test]
    fn prop_star_matches_all() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "abc"));
        assert!(glob_match("*", "xyz123"));
    }
}

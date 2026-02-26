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

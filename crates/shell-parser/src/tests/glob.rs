use crate::glob::{glob_match, glob_replace, glob_strip_prefix, glob_strip_suffix};

// --- Glob star in parsing ---
// (parse-level glob tests like test_glob_star, test_glob_question, test_glob_bracket
//  live in parse.rs / expansion.rs; these tests cover the glob matching functions)

// -- Glob matching --

#[test]
fn glob_match_literal() {
    assert!(glob_match("hello", "hello"));
    assert!(!glob_match("hello", "world"));
}

#[test]
fn glob_match_star() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*.txt", "file.txt"));
    assert!(!glob_match("*.txt", "file.rs"));
    assert!(glob_match("*/", "foo/"));
    assert!(glob_match("*/", "bar/baz/"));
}

#[test]
fn glob_match_question() {
    assert!(glob_match("?", "a"));
    assert!(!glob_match("?", ""));
    assert!(!glob_match("?", "ab"));
    assert!(glob_match("a?c", "abc"));
}

#[test]
fn glob_match_bracket() {
    assert!(glob_match("[abc]", "a"));
    assert!(glob_match("[abc]", "b"));
    assert!(!glob_match("[abc]", "d"));
    assert!(glob_match("[a-z]", "m"));
    assert!(!glob_match("[a-z]", "M"));
}

#[test]
fn glob_match_bracket_negate() {
    assert!(!glob_match("[!abc]", "a"));
    assert!(glob_match("[!abc]", "d"));
    assert!(glob_match("[^abc]", "d"));
}

#[test]
fn glob_match_empty() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
    assert!(glob_match("*", ""));
}

// -- Glob strip prefix --

#[test]
fn glob_strip_prefix_shortest() {
    assert_eq!(
        glob_strip_prefix("*/", "/usr/local/bin", false),
        "usr/local/bin"
    );
}

#[test]
fn glob_strip_prefix_longest() {
    assert_eq!(glob_strip_prefix("*/", "/usr/local/bin", true), "bin");
}

#[test]
fn glob_strip_prefix_no_match() {
    assert_eq!(glob_strip_prefix("xyz", "hello", false), "hello");
}

// -- Glob strip suffix --

#[test]
fn glob_strip_suffix_shortest() {
    assert_eq!(glob_strip_suffix(".*", "file.tar.gz", false), "file.tar");
}

#[test]
fn glob_strip_suffix_longest() {
    assert_eq!(glob_strip_suffix(".*", "file.tar.gz", true), "file");
}

#[test]
fn glob_strip_suffix_no_match() {
    assert_eq!(glob_strip_suffix("xyz", "hello", false), "hello");
}

// -- Glob replace --

#[test]
fn glob_replace_first_only() {
    assert_eq!(glob_replace("o", "foobar", "0", false), "f0obar");
}

#[test]
fn glob_replace_all_occurrences() {
    assert_eq!(glob_replace("o", "foobar", "0", true), "f00bar");
}

#[test]
fn glob_replace_with_wildcard() {
    assert_eq!(
        glob_replace("*.txt", "hello.txt", "goodbye", false),
        "goodbye"
    );
}

// -- Glob: bracket with star backtrack --

#[test]
fn glob_bracket_no_match_backtracks_over_star() {
    // Pattern: *[0-9] should match "abc3" (star eats "abc", bracket matches "3")
    assert!(glob_match("*[0-9]", "abc3"));
    // But not "abcx"
    assert!(!glob_match("*[0-9]", "abcx"));
}

#[test]
fn glob_bracket_no_match_no_star_fails() {
    // [0-9] alone should not match "a"
    assert!(!glob_match("[0-9]", "a"));
}

#[test]
fn glob_malformed_bracket_treated_as_literal() {
    // "[abc" has no closing ] — treated as literal '['
    assert!(glob_match("[abc", "[abc"));
    assert!(!glob_match("[abc", "a"));
}

#[test]
fn glob_malformed_bracket_with_star_backtracks() {
    // "*[abc" — malformed bracket after star; '[' treated as literal
    assert!(glob_match("*[abc", "xyz[abc"));
}

#[test]
fn glob_malformed_bracket_no_star_mismatch() {
    // "[xyz" treated as literal '[' — doesn't match 'a'
    assert!(!glob_match("[xyz", "a"));
}

#[test]
fn glob_bracket_literal_close() {
    // []] matches ']'
    assert!(glob_match("[]]", "]"));
}

#[test]
fn glob_bracket_negate_close() {
    // [!]] matches anything except ']'
    assert!(glob_match("[!]]", "a"));
    assert!(!glob_match("[!]]", "]"));
}

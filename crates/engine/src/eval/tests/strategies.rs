//! Proptest input strategies for shell-syntax shapes.
//!
//! `arb_shell_chars` produces a single line of shell-ish character soup —
//! enough quoting, sigil, and operator characters that the parser hits real
//! shapes (compound commands, substitutions, redirections) rather than
//! spending all its budget on parser-bypassing noise.
//!
//! `arb_with_heredoc` composes `arb_shell_chars` content with a synthesised
//! `<<DELIM` / `<<'DELIM'` heredoc, with matching or mismatched closers, so
//! quoted-heredoc-body invariants are reachable.

use proptest::prelude::*;

pub(crate) fn arb_shell_chars() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r#"[a-zA-Z0-9 ;|&"'$()<>/\\\-`#=]{0,80}"#).unwrap()
}

/// Narrower alphabet without quoting or escapes — the engine's
/// `find_balanced_paren` skips quoted regions and `\X` escapes while the
/// lexer's `read_balanced_parens_checked` counts depth only, so the two
/// matchers only have to agree when those skipping rules are inert.
pub(crate) fn arb_unquoted_shell_chars() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r#"[a-zA-Z0-9 ;|&$()<>/\-#=]{0,80}"#).unwrap()
}

pub(crate) fn arb_with_heredoc() -> impl Strategy<Value = String> {
    let delim = "[A-Z]{1,6}";
    (
        proptest::string::string_regex(delim).unwrap(),
        proptest::string::string_regex(delim).unwrap(),
        any::<bool>(),
        any::<bool>(),
        arb_shell_chars(),
        arb_shell_chars(),
        arb_shell_chars(),
    )
        .prop_map(
            |(open_delim, alt_delim, quote_opener, mismatch_close, prelude, body, trailer)| {
                let open = if quote_opener {
                    format!("'{open_delim}'")
                } else {
                    open_delim.clone()
                };
                let close = if mismatch_close {
                    alt_delim
                } else {
                    open_delim
                };
                format!("{prelude}cat <<{open}\n{body}\n{close}\n{trailer}")
            },
        )
}

/// Inject a literal `'…'` region into `arb_shell_chars` output. Returns
/// `(input, quoted_start, quoted_end)` — the byte range of the bytes between
/// the opening and closing single quotes (exclusive of the quotes
/// themselves).
pub(crate) fn arb_with_single_quoted_region() -> impl Strategy<Value = (String, usize, usize)> {
    (
        arb_shell_chars(),
        proptest::string::string_regex("[a-zA-Z0-9 ]{1,40}").unwrap(),
        arb_shell_chars(),
    )
        .prop_map(|(prefix, quoted, suffix)| {
            let start = prefix.len() + 1;
            let end = start + quoted.len();
            let input = format!("{prefix}'{quoted}'{suffix}");
            (input, start, end)
        })
}

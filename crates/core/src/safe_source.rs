//! Offset-preserving sanitisation for source text addressed by byte-offset
//! spans (the snippet rendered by miette diagnostics).
//!
//! [`SafeText`](crate::SafeText) escapes control characters by *expansion*
//! (`\x1b` → four bytes), which shifts every byte offset after it and misaligns
//! span underlines. [`SafeSource`] instead replaces each *dangerous* control
//! character with a printable placeholder of *equal UTF-8 byte length*, so the
//! byte length of the source is unchanged and any `SourceSpan` valid against the
//! original remains in-bounds and correctly aligned against the sanitised source.
//!
//! Line feed (`\n`) and tab (`\t`) are deliberately preserved: in an
//! offset-addressed *multi-line* source snippet they are structural — the
//! renderer (miette) splits lines on `\n` and lays out `\t`, and a span's
//! line/column is derived from them. Scrubbing them would collapse the snippet
//! and misplace every caret. They are also not injection vectors: neither moves
//! the cursor arbitrarily nor starts an escape sequence the way `\x1b` does.
//! Every other control character (notably `\x1b`) is scrubbed.

/// Single-byte printable placeholder substituted for each byte of a scrubbed
/// control character. A C0 control (1 byte) becomes one of these; a C1 control
/// (2 bytes in UTF-8) becomes two, keeping the byte length identical.
const PLACEHOLDER: u8 = b'?';

/// Whether a control character must be scrubbed. `\n` and `\t` are structural
/// whitespace preserved for multi-line layout; all other control chars are
/// scrubbed.
fn is_dangerous(c: char) -> bool {
    c.is_control() && c != '\n' && c != '\t'
}

/// Source text sanitised for offset-addressed rendering: guaranteed to contain
/// no control character other than the structural `\n`/`\t`, with byte length
/// identical to its input so span offsets stay valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSource(String);

impl SafeSource {
    /// Sanitise source text, replacing every control character with a printable
    /// placeholder of equal UTF-8 byte length. Length-preserving by construction.
    #[must_use]
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(scrub_control(s.as_ref()))
    }

    /// Borrow the sanitised string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SafeSource {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

/// Replace each control character with `PLACEHOLDER` repeated to match the
/// character's UTF-8 byte length, so the output is the same byte length as the
/// input and offsets are preserved.
fn scrub_control(s: &str) -> String {
    if !s.chars().any(is_dangerous) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_dangerous(c) {
            for _ in 0..c.len_utf8() {
                out.push(PLACEHOLDER as char);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Sanitised source carries no dangerous control character (only the
        /// structural `\n`/`\t` may remain), for any input.
        #[test]
        fn prop_new_has_no_dangerous_control_char(s in ".*") {
            let r = SafeSource::new(&s);
            prop_assert!(
                !r.as_str().chars().any(super::is_dangerous),
                "SafeSource carries a dangerous control character: {:?}",
                r.as_str()
            );
        }

        /// In particular, no `\x1b` (the ANSI-injection vector) survives.
        #[test]
        fn prop_new_strips_escape(s in ".*") {
            let r = SafeSource::new(&s);
            prop_assert!(!r.as_str().contains('\x1b'));
        }

        /// Byte length is preserved, so a span valid against the input stays
        /// in-bounds against the result.
        #[test]
        fn prop_new_preserves_byte_length(s in ".*") {
            let r = SafeSource::new(&s);
            prop_assert_eq!(r.as_str().len(), s.len());
        }

        /// Any span chosen against the original remains in-bounds and on a char
        /// boundary against the sanitised source.
        #[test]
        fn prop_span_stays_in_bounds(s in ".{1,200}", a in 0usize..200, b in 0usize..200) {
            let r = SafeSource::new(&s);
            let lo = a.min(b) % (s.len() + 1);
            let hi = a.max(b) % (s.len() + 1);
            // The chosen offsets are valid against the input; preserved length +
            // identical char boundaries (placeholders are ASCII, slotted only
            // where a control char already sat) keep them valid against output.
            prop_assert!(hi <= r.as_str().len());
            prop_assert!(r.as_str().is_char_boundary(lo) || !s.is_char_boundary(lo));
            prop_assert!(r.as_str().is_char_boundary(hi) || !s.is_char_boundary(hi));
        }

        /// Control-free input is returned verbatim.
        #[test]
        fn prop_control_free_input_is_verbatim(s in "[^\u{0}-\u{1f}\u{7f}-\u{9f}]*") {
            let r = SafeSource::new(&s);
            prop_assert_eq!(r.as_str(), &s);
        }
    }

    #[test]
    fn newline_and_tab_are_preserved() {
        // Structural whitespace must survive so a multi-line source snippet
        // keeps its line layout and span line/column mapping.
        let r = SafeSource::new("a\n\tb");
        assert_eq!(r.as_str(), "a\n\tb");
    }

    #[test]
    fn escape_becomes_placeholder() {
        let r = SafeSource::new("a\x1b[31mb");
        assert!(!r.as_str().contains('\x1b'));
        assert_eq!(r.as_str().len(), "a\x1b[31mb".len());
    }

    #[test]
    fn c1_control_keeps_byte_length() {
        // U+0085 NEL is a 2-byte control char in UTF-8.
        let src = "a\u{0085}b";
        let r = SafeSource::new(src);
        assert_eq!(r.as_str().len(), src.len());
        assert!(!r.as_str().chars().any(|c| c.is_control()));
    }
}

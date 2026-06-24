//! Display-safe text: the single escaping choke point for input-derived text
//! that reaches a terminal-output surface.
//!
//! A raw control character corrupts a TTY surface (a newline breaks a line,
//! `\x1b` injects a terminal escape), and output text routinely interpolates
//! input-derived names parsed from the command under evaluation — an
//! adversary-influenced surface.
//!
//! [`SafeText`] makes display-safety hold *by construction*: its only
//! constructor control-escapes, the field is private, and there is no
//! `From`/`Into` that bypasses escaping — so no output-building site can emit an
//! unescaped string, and a future site cannot regress the invariant by
//! forgetting to escape. It lives in `may-i-core`, the leaf both `may-i-engine`
//! (Reason text) and `may-i-output` (Layout content) already depend on, so one
//! implementation backs every surface.

use std::fmt;

/// Display-safe text: guaranteed to contain no raw control character. The sole
/// constructor ([`SafeText::new`]) escapes, so the invariant holds by
/// construction rather than by an escape call repeated at each call site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeText(String);

impl SafeText {
    /// Build display-safe text from any string, control-escaping it. Idempotent:
    /// escaping already-escaped text is a no-op, because the escapes
    /// (`char::escape_default`) are plain ASCII and the map only touches
    /// `char::is_control()`.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(escape_control(&s.into()))
    }

    /// Borrow the escaped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SafeText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

// Deliberately no `From`/`Into`: control-escaping is a normalisation, not the
// cheap, lossless conversion `From` promises. Every construction goes through the
// explicit `SafeText::new`, keeping the escape visible at the one choke point.
// `Deref<Target = str>` (above) already covers borrowing/comparison ergonomics,
// so no `AsRef`/`PartialEq<str>` impls are needed.

impl fmt::Display for SafeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Escape control characters (e.g. newlines from `$'\n'` ANSI-C quoting) so an
/// interpolated, input-derived name cannot break a single-line surface or inject
/// a terminal escape. Per-character and control-only: non-control bytes
/// (including backslashes and quotes) pass through, so the map is idempotent over
/// its own output.
fn escape_control(s: &str) -> String {
    if !s.chars().any(|c| c.is_control()) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
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
        /// The constructor's contract: whatever the input, the result carries no
        /// raw control character. This is the single proof that replaces the
        /// per-site escape discipline.
        #[test]
        fn prop_new_has_no_control_char(s in ".*") {
            let r = SafeText::new(s);
            prop_assert!(
                !r.as_str().chars().any(|c| c.is_control()),
                "SafeText carries a raw control character: {:?}",
                r.as_str()
            );
        }

        /// Idempotent: escaping an already-built value changes nothing, so the
        /// sink can wrap composed text without double-escaping.
        #[test]
        fn prop_new_is_idempotent(s in ".*") {
            let once = SafeText::new(s);
            let twice = SafeText::new(once.as_str());
            prop_assert_eq!(once.as_str(), twice.as_str());
        }

        /// Control-free input is returned verbatim — escaping never mangles text
        /// that was already safe (e.g. static template text).
        #[test]
        fn prop_control_free_input_is_verbatim(s in "[ -~]*") {
            let r = SafeText::new(&s);
            prop_assert_eq!(r.as_str(), &s);
        }
    }

    #[test]
    fn newline_is_escaped() {
        let r = SafeText::new("a\nb");
        assert_eq!(r.as_str(), "a\\nb");
        assert!(!r.as_str().contains('\n'));
    }
}

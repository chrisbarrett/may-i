//! Display-safe command-evaluation reasons.
//!
//! A reason is surfaced as a single value: a JSON string on the Claude Code
//! hook surface (`permissionDecisionReason`) and a raw-printed line on the
//! `may-i eval` TTY surface. A raw control character corrupts the latter (a
//! newline breaks the line, `\x1b` injects a terminal escape), and the reason
//! interpolates input-derived names parsed from the command under evaluation —
//! an adversary-influenced surface.
//!
//! [`DisplaySafe`] makes display-safety hold *by construction*: its only constructor
//! control-escapes, the field is private, and [`crate::EvalResult`] stores
//! `Option<DisplaySafe>` — so no reason-building site can emit an unescaped reason,
//! and a future site cannot regress the invariant by forgetting to escape.

use std::fmt;

/// A display-safe reason string: guaranteed to contain no raw control
/// character. The sole constructor ([`DisplaySafe::new`]) escapes, so the invariant
/// holds by construction rather than by an escape call repeated at each
/// reason-building site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplaySafe(String);

impl DisplaySafe {
    /// Build a reason from any string, control-escaping it. Idempotent:
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

impl std::ops::Deref for DisplaySafe {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

// Deliberately no `From`/`Into`: control-escaping is a normalisation, not the
// cheap, lossless conversion `From` promises. Every construction goes through
// the explicit `DisplaySafe::new`, keeping the escape visible at the one choke point.
// `Deref<Target = str>` (above) already covers borrowing/comparison ergonomics,
// so no `AsRef`/`PartialEq<str>` impls are needed.

impl fmt::Display for DisplaySafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Escape control characters (e.g. newlines from `$'\n'` ANSI-C quoting) so an
/// interpolated, input-derived name cannot break the single-line reason
/// surface. Per-character and control-only: non-control bytes (including
/// backslashes and quotes) pass through, so the map is idempotent over its own
/// output.
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
        /// The constructor's contract: whatever the input, the resulting
        /// reason carries no raw control character. This is the single proof
        /// that replaces the per-site escape discipline.
        #[test]
        fn prop_reason_new_has_no_control_char(s in ".*") {
            let r = DisplaySafe::new(s);
            prop_assert!(
                !r.as_str().chars().any(|c| c.is_control()),
                "DisplaySafe carries a raw control character: {:?}",
                r.as_str()
            );
        }

        /// Idempotent: escaping an already-built reason changes nothing, so the
        /// sink can wrap composed reasons (e.g. an annotated inner reason)
        /// without double-escaping.
        #[test]
        fn prop_reason_new_is_idempotent(s in ".*") {
            let once = DisplaySafe::new(s);
            let twice = DisplaySafe::new(once.as_str());
            prop_assert_eq!(once.as_str(), twice.as_str());
        }

        /// Control-free input is returned verbatim — escaping never mangles a
        /// reason that was already safe (e.g. static template text).
        #[test]
        fn prop_control_free_input_is_verbatim(s in "[ -~]*") {
            // Printable ASCII: no control characters, so escaping must be a
            // no-op. (Full-range escaping is covered by the two properties
            // above.)
            let r = DisplaySafe::new(&s);
            prop_assert_eq!(r.as_str(), &s);
        }
    }

    #[test]
    fn newline_is_escaped() {
        let r = DisplaySafe::new("a\nb");
        assert_eq!(r.as_str(), "a\\nb");
        assert!(!r.as_str().contains('\n'));
    }
}

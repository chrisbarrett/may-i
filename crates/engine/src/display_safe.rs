//! Display-safe command-evaluation reasons.
//!
//! A reason is surfaced as a single value: a JSON string on the Claude Code hook
//! surface (`permissionDecisionReason`) and a raw-printed line on the
//! `may-i eval` TTY surface. A raw control character corrupts the latter (a
//! newline breaks the line, `\x1b` injects a terminal escape), and the reason
//! interpolates input-derived names parsed from the command under evaluation —
//! an adversary-influenced surface.
//!
//! The escaping choke point now lives in `may-i-core` as
//! [`SafeText`](may_i_core::SafeText), shared by every terminal-output surface.
//! `DisplaySafe` is retained as an alias so the Reason path's spelling is
//! unchanged while the implementation is single-sourced.

/// A display-safe reason string: alias of the shared
/// [`may_i_core::SafeText`] choke point. Its only constructor control-escapes,
/// the field is private, and there is no escape-bypassing `From`/`Into`.
pub type DisplaySafe = may_i_core::SafeText;

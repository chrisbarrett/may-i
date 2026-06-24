//! The single output sink: the only module that acquires and writes the
//! process `stdout`/`stderr` streams.
//!
//! Every other module reaches a stream through one of these functions. The
//! entry points accept only escape-safe input — a [`Layout`] (rendered with a
//! [`Terminal`]), a [`Styled`] line, a [`SafeText`] line, or a serialisable
//! value (JSON, whose control bytes serde escapes) — plus a controlled
//! `with_*` writer bridge for the per-subcommand builders, which take a writer
//! by the renderer protocol. Because the only bytes handed to that writer come
//! from `Styled`/`SafeText`-derived rendering, no raw control character or
//! caller-supplied ANSI can reach a stream.
//!
//! This module carries the sole `#[allow(clippy::print_stdout, …)]`; the
//! workspace denies those lints everywhere else, and a prek hook bans naming a
//! raw stream handle outside this file.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{IsTerminal, StderrLock, StdoutLock, Write};

use may_i_core::SafeText;
use may_i_output::{Layout, Styled, Terminal, write_layout, write_line};

/// Whether colour should be emitted on `stdout`: honoured `NO_COLOR` and a tty
/// check. This is the single enablement decision for the whole CLI.
#[must_use]
pub fn stdout_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// A detected terminal with the central colour decision applied.
#[must_use]
pub fn terminal() -> Terminal {
    Terminal::detect().with_color(stdout_color())
}

/// Whether `stdout` is a terminal. The sole tty probe.
#[must_use]
pub fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

/// Whether colour should be emitted on `stderr`: `NO_COLOR` honoured plus a tty
/// check. Used by the interactive trust-review surface, which renders to stderr.
#[must_use]
pub fn stderr_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

/// The interactive terminal handle for the trust-review TUI, which needs cursor
/// control (clear-screen, read-char) beyond plain writes. This is the sole
/// acquisition of a `console::Term` stream handle; keeping it here lets the prek
/// hook ban `console::Term::std*` everywhere else. The TUI's *content* is built
/// from `Styled`-rendered (escape-safe) strings, so only terminal control — not
/// injectable bytes — flows through this handle.
#[must_use]
pub fn interactive_term() -> console::Term {
    console::Term::stderr()
}

/// Run `f` with a locked `stdout` writer. The renderer protocol's builders take
/// a writer; this is the only place that writer originates.
pub fn with_stdout<R>(f: impl FnOnce(&mut StdoutLock<'static>) -> R) -> R {
    let mut lock = std::io::stdout().lock();
    let r = f(&mut lock);
    let _ = lock.flush();
    r
}

/// Run `f` with a locked `stderr` writer.
pub fn with_stderr<R>(f: impl FnOnce(&mut StderrLock<'static>) -> R) -> R {
    let mut lock = std::io::stderr().lock();
    let r = f(&mut lock);
    let _ = lock.flush();
    r
}

/// Render a layout tree to `stdout`.
pub fn layout(layout: &Layout, term: &Terminal) {
    with_stdout(|w| write_layout(w, layout, term));
}

/// Write a styled line (plus newline) to `stdout`.
pub fn styled_line(line: &Styled, term: &Terminal) {
    with_stdout(|w| write_line(w, line, term));
}

/// Write a display-safe plain line (plus newline) to `stdout`.
pub fn line(text: &SafeText) {
    with_stdout(|w| {
        let _ = writeln!(w, "{text}");
    });
}

/// Write a display-safe plain line (plus newline) to `stderr`.
pub fn eline(text: &SafeText) {
    with_stderr(|w| {
        let _ = writeln!(w, "{text}");
    });
}

/// Serialise `value` as a single JSON line to `stdout`. serde escapes control
/// bytes to `\uXXXX`, so the result is ANSI-safe by construction.
pub fn json(value: &impl serde::Serialize) {
    with_stdout(|w| {
        let _ = writeln!(
            w,
            "{}",
            serde_json::to_string(value).expect("response serialization is infallible")
        );
    });
}

/// Drain the config crate's recorded load-time advisories and emit each to
/// `stderr` as a display-safe line. The host calls this after a config load so
/// the config library never writes to a stream itself.
pub fn flush_config_advisories() {
    for message in may_i_config::take_advisories() {
        eline(&SafeText::new(message));
    }
}

/// Render a miette diagnostic report to `stderr`. The report's source and
/// interpolations are sanitised at construction (see `shape_diag` /
/// `SafeText`-wrapped `miette!`), so miette's own SGR is trusted here.
pub fn report(report: &miette::Report) {
    with_stderr(|w| {
        let _ = writeln!(w, "{report:?}");
    });
}

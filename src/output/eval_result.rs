// Intent: render `cmd_eval` text output as a single per-subcommand builder.
//
// `cmd_eval` constructs an `EvalOutput` and hands it to `.render(w,
// pipeline)`. The builder owns the rendering script: prelude advisories →
// trust warning → trace block → result block. The leaf renderer below is
// crate-private and reachable only through this builder.

use std::io::Write;
use std::path::Path;

use colored::Colorize;
use may_i_engine::EvalResult;
use may_i_pp::colorize_atom;

use super::{Terminal, colorize_decision_keyword, shorten_home, write_trace};
use crate::annotation::TraceEntry;

/// Per-subcommand text-output renderer for `may-i eval`. Pure body
/// rendering (trace + decision block); prelude advisories and trust
/// warnings are owned by `CommandPipeline::run`.
pub struct EvalOutput<'a> {
    pub config_path: &'a Path,
    pub trace_entries: &'a [TraceEntry],
    pub command: &'a str,
    pub colored_command: &'a str,
    pub eval_result: &'a EvalResult,
}

impl EvalOutput<'_> {
    /// Emit the `may-i eval` text body (trace + result block) to `w`.
    pub fn render(&self, w: &mut impl Write, terminal: &Terminal) {
        let display_path = shorten_home(self.config_path);
        render_eval_result(
            w,
            terminal,
            self.command,
            self.colored_command,
            self.trace_entries,
            self.eval_result,
            &display_path,
        );
    }
}

/// Render the trace (when non-empty) and result block to `w`.
pub(crate) fn render_eval_result(
    w: &mut impl Write,
    term: &Terminal,
    command: &str,
    colored_command: &str,
    traces: &[TraceEntry],
    result: &EvalResult,
    display_path: &str,
) {
    if !traces.is_empty() {
        let _ = writeln!(w, "\n{}\n", "Trace".bold());
        write_trace(w, traces, command, "  ", term);
    }

    let _ = writeln!(w, "\n{}\n", "Result".bold());
    let _ = writeln!(w, "  {colored_command}");
    let _ = writeln!(w);
    {
        let keyword = format!(":{}", result.decision);
        let colored_keyword = colorize_decision_keyword(&keyword);
        match &result.reason {
            Some(reason) => {
                let quoted = format!("\"{reason}\"");
                let _ = writeln!(
                    w,
                    "  {} {colored_keyword} {}",
                    "→".dimmed(),
                    colorize_atom(&quoted, true)
                );
            }
            None => {
                let _ = writeln!(w, "  {} {colored_keyword}", "→".dimmed());
            }
        }
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "  {} {}", "config:".dimmed(), display_path.dimmed());
}

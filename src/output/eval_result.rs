// Intent: render the body of an `eval` invocation.
//
// Builds the trace block (when traces exist) followed by the result block:
// colourised command, decision keyword + optional reason, and the config
// path. Layout assembly stays inside this module — callers express intent.

use std::io::Write;

use colored::Colorize;
use may_i_engine::EvalResult;
use may_i_pp::colorize_atom;

use super::{Terminal, colorize_decision_keyword, write_trace};
use crate::annotation::TraceEntry;

/// Render the trace (when non-empty) and result block to `w`.
pub fn render_eval_result(
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

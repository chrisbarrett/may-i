// Format command — canonicalise and pretty-print config files.
//
// Pipeline mirrors `cmd_migrate.rs` but applies the canonicaliser sort pass
// instead of v1 → v2 rewrites. No semantic changes are made; only whitespace
// and declaration order are normalised.
//
// Three input modes:
//   - File mode: explicit paths, format in place.
//   - Walk mode: no positional args + tty stdin → walk the load graph.
//   - Stdin mode: piped stdin or `-` → read stdin, write stdout.
//
// `--check` short-circuits all writes and signals via exit code only:
//   0 = clean, 1 = would change, 2 = error.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use may_i::sink;
use may_i_config::{canonicalise_forms, parse_config_from_sexprs};
use may_i_pp::detect_column_width;
use may_i_sexpr::parse_cst;

/// Per-input outcome severity. Final exit code is the highest severity
/// across all inputs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Clean = 0,
    WouldChange = 1,
    Error = 2,
}

impl Severity {
    fn to_exit(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

/// Top-level entry point. Returns the appropriate `ExitCode` so the binary
/// can propagate exit-code semantics (0/1/2) without wrapping in miette's
/// error path.
pub(crate) fn cmd_fmt(
    config_path: Option<&Path>,
    files: Vec<String>,
    check: bool,
) -> miette::Result<ExitCode> {
    // Reject mixed `-` + paths at argv parse.
    let dash_count = files.iter().filter(|f| f.as_str() == "-").count();
    if dash_count > 0 && files.len() > 1 {
        sink::with_stderr(|w| {
            let _ = writeln!(w, "error: mixed `-` and file arguments are not supported");
        });
        return Ok(Severity::Error.to_exit());
    }

    // Explicit stdin: `-` as sole positional argument.
    if dash_count == 1 {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: failed to read stdin: {e}");
            });
            return Ok(Severity::Error.to_exit());
        }
        return Ok(run_stdin_text(&buf, check));
    }

    // Implicit stdin: no positional args AND stdin is piped (non-tty) AND
    // actually carries data. An empty pipe falls through to walk mode so
    // the bare command works in non-interactive shells (CI, test
    // harnesses, hooks) where stdin is not a tty even when no input is
    // intended.
    if files.is_empty() && !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: failed to read stdin: {e}");
            });
            return Ok(Severity::Error.to_exit());
        }
        if !buf.trim().is_empty() {
            return Ok(run_stdin_text(&buf, check));
        }
    }

    // File mode or walk mode.
    let paths: Vec<PathBuf> = if files.is_empty() {
        let primary = may_i_config::resolve_path(config_path)?;
        let walked = may_i_config::walk_load_graph(&primary)?;
        sink::flush_config_advisories();
        walked
    } else {
        files.into_iter().map(PathBuf::from).collect()
    };

    let mut overall = Severity::Clean;
    for path in &paths {
        let sev = process_file(path, check);
        if sev > overall {
            overall = sev;
        }
    }
    Ok(overall.to_exit())
}

/// Format the config file at `path` (or check it). Errors are reported on
/// stderr and reflected in the returned severity; processing continues for
/// the remaining files.
fn process_file(path: &Path, check: bool) -> Severity {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: failed to read {}: {e}", path.display());
            });
            return Severity::Error;
        }
    };

    let (canonical, severity) = match canonical_text(&source) {
        Ok((text, legacy)) => {
            if legacy {
                sink::with_stderr(|w| {
                    let _ = writeln!(
                        w,
                        "warning: {} contains legacy syntax — run `may-i migrate` to update it",
                        path.display()
                    );
                });
            }
            (text, Severity::Clean)
        }
        Err(msg) => {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: {}: {msg}", path.display());
            });
            return Severity::Error;
        }
    };

    if source == canonical {
        return severity;
    }

    if check {
        return Severity::WouldChange;
    }

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: failed to stat {}: {e}", path.display());
            });
            return Severity::Error;
        }
    };
    if metadata.permissions().readonly() {
        sink::with_stderr(|w| {
            let _ = writeln!(w, "warning: skipped, not writable: {}", path.display());
        });
        return severity;
    }
    if let Err(e) = std::fs::write(path, &canonical) {
        sink::with_stderr(|w| {
            let _ = writeln!(w, "error: failed to write {}: {e}", path.display());
        });
        return Severity::Error;
    }
    severity
}

/// Stdin filter mode. Formats `source` and writes to stdout (or stays
/// silent in `--check` mode).
fn run_stdin_text(source: &str, check: bool) -> ExitCode {
    let (canonical, legacy) = match canonical_text(source) {
        Ok(p) => p,
        Err(msg) => {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "error: <stdin>: {msg}");
            });
            return Severity::Error.to_exit();
        }
    };
    if legacy {
        sink::with_stderr(|w| {
            let _ = writeln!(
                w,
                "warning: <stdin> contains legacy syntax — run `may-i migrate` to update it"
            );
        });
    }

    if check {
        return if source == canonical {
            Severity::Clean.to_exit()
        } else {
            Severity::WouldChange.to_exit()
        };
    }

    sink::with_stdout(|w| {
        let _ = write!(w, "{canonical}");
    });
    Severity::Clean.to_exit()
}

/// Parse, canonicalise, render. Returns `(canonical_text, is_legacy)`.
/// `is_legacy` is `true` when the canonical-syntax loader rejects the
/// rendered output, indicating legacy forms (e.g. `(effect :allow)`,
/// `(may-i *)`) survive in the input. The text is returned unchanged
/// either way — `fmt` never silently rewrites legacy forms.
fn canonical_text(source: &str) -> Result<(String, bool), String> {
    let (forms, parse_errors) = parse_cst(source);
    if let Some(err) = parse_errors.first() {
        return Err(format!("parse error: {err}"));
    }

    // Formless inputs (comments-only, whitespace-only) carry no forms to
    // canonicalise; pretty-printing nothing erases the file. Preserve verbatim.
    if forms.is_empty() {
        return Ok((source.to_string(), false));
    }

    let canon = canonicalise_forms(forms);
    let width = detect_column_width(source);

    // Preserve trailing newline iff the input had one.
    let mut text = canon
        .iter()
        .map(|f| f.pretty_serialize(width))
        .collect::<Vec<_>>()
        .join("");
    let had_trailing = source.ends_with('\n');
    if had_trailing && !text.ends_with('\n') {
        text.push('\n');
    } else if !had_trailing && text.ends_with('\n') {
        text.truncate(text.trim_end_matches('\n').len());
    }

    let legacy = !is_canonical_loadable(&text);
    Ok((text, legacy))
}

/// Probe whether the canonical-syntax parser accepts the rendered output.
/// `(load …)` forms are tolerated — the IO layer expands them at load time.
fn is_canonical_loadable(text: &str) -> bool {
    let (sexprs, errs) = may_i_sexpr::parse(text);
    if !errs.is_empty() {
        return false;
    }
    let non_load: Vec<may_i_sexpr::Sexpr> = sexprs
        .into_iter()
        .filter(|f| {
            f.as_list()
                .and_then(|l| l.first())
                .and_then(|t| t.as_atom())
                != Some("load")
        })
        .collect();
    if non_load.is_empty() {
        return true;
    }
    parse_config_from_sexprs(&non_load).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn comment_or_whitespace_input() -> impl Strategy<Value = String> {
        let comment = r";;[ \tA-Za-z0-9._-]*\n";
        let whitespace = r"[ \t\n]+";
        prop::collection::vec(prop_oneof![comment, whitespace], 1..16)
            .prop_map(|chunks| chunks.concat())
    }

    proptest! {
        #[test]
        fn formless_input_parses_clean(source in comment_or_whitespace_input()) {
            let (forms, errors) = parse_cst(&source);
            prop_assert!(forms.is_empty(), "comments+whitespace yields no forms");
            prop_assert!(errors.is_empty(), "comments+whitespace is legal trivia");
        }

        #[test]
        fn formless_input_round_trips_byte_identical(source in comment_or_whitespace_input()) {
            let (text, legacy) = canonical_text(&source).expect("formless parses cleanly");
            prop_assert!(!legacy, "formless input is not legacy");
            prop_assert_eq!(&text, &source, "formless input must be preserved verbatim");
        }
    }
}

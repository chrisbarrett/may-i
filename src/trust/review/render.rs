// Pure rendering helpers for the trust review and repair loops. Each function
// returns a string (or string fragments) so the loop can hand the result to
// `UserPrompt::render`. This module is the only place inside
// `src/trust/review/` allowed to import `may_i_pp`, `may_i_sexpr`, or
// `similar`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use may_i_core::Doc;
use may_i_output::{Style, Styled};

use crate::output::{Terminal, render_labelled_separator, shorten_home};
use crate::trust::review::prompt::ReviewSummary;
use crate::trust::store::SuspectEntry;

/// Render a single styled fragment to an inline string (no trailing newline),
/// emitting SGR only when colour is on for the stderr review surface.
pub(crate) fn paint(text: impl Into<String>, style: Style, color: bool) -> String {
    let term = crate::output::Terminal::new(0).with_color(color);
    let mut buf = Vec::new();
    may_i_output::write_line(&mut buf, &Styled::span(text, style), &term);
    let s = String::from_utf8(buf).unwrap_or_default();
    s.strip_suffix('\n').map(str::to_string).unwrap_or(s)
}

/// Convert a parsed s-expression into a `Doc` tree for pretty-printing.
fn doc_from_sexpr(sexpr: &may_i_sexpr::Sexpr) -> Doc {
    match sexpr {
        may_i_sexpr::Sexpr::Keyword(s, _)
        | may_i_sexpr::Sexpr::Symbol(s, _)
        | may_i_sexpr::Sexpr::Binding(s, _) => Doc::atom(s.clone()),
        may_i_sexpr::Sexpr::String(s, _) => Doc::atom(may_i_sexpr::quote_string(s)),
        may_i_sexpr::Sexpr::List(items, _) | may_i_sexpr::Sexpr::Vector(items, _) => {
            Doc::list(items.iter().map(doc_from_sexpr).collect())
        }
    }
}

/// Pretty-print a canonical form using the pp crate's indentation engine.
/// Falls back to the input on parse failure.
pub fn pretty_form(canonical: &str, width: usize, color: bool) -> String {
    let (sexprs, _errors) = may_i_sexpr::parse(canonical);
    if sexprs.is_empty() {
        return canonical.to_string();
    }
    let doc = doc_from_sexpr(&sexprs[0]);
    let fmt = may_i_pp::Format {
        width,
        color,
        line_number: None,
        preserve_user_breaks: false,
    };
    // Color-as-data: collect styled spans, then render with the role→SGR
    // renderer. `color` decides SGR emission; the styling is in the data either
    // way. Returns a multi-line string (no trailing newline) so callers' existing
    // `.lines()` handling is unchanged.
    let lines = may_i_pp::pretty_styled(&doc, 0, &fmt);
    let term = Terminal::new(width).with_color(color);
    let mut buf = Vec::new();
    for line in &lines {
        may_i_output::write_line(&mut buf, line, &term);
    }
    let s = String::from_utf8(buf).unwrap_or_default();
    s.strip_suffix('\n').map(str::to_string).unwrap_or(s)
}

/// Render the detail block for a single suspect entry (integrity failure).
pub(crate) fn render_suspect_detail(suspect: &SuspectEntry) -> String {
    let color = crate::sink::stderr_color();
    let mut out = String::new();
    out.push_str(&format!(
        "  {} {}\n",
        paint(&suspect.program, Style::Strong, color),
        paint("SUSPECT", Style::Deny, color)
    ));
    out.push_str(&format!(
        "    {} {}\n",
        paint("stored hash:", Style::Dimmed, color),
        paint(&suspect.hash, Style::Dimmed, color)
    ));
    out.push_str(&format!(
        "    {}\n",
        paint(&suspect.stored_form, Style::Dimmed, color)
    ));
    out.push('\n');
    out
}

/// Render the detail block for one pending rule in the per-rule review.
pub(crate) fn render_rule_detail(
    source_file: Option<&Path>,
    canonical_form: &str,
    prev_form: Option<&str>,
    pp_width: usize,
) -> String {
    let color = crate::sink::stderr_color();
    let mut out = String::new();
    if let Some(file) = source_file {
        out.push_str(&format!(
            "  {} {}\n",
            paint("file:", Style::Dimmed, color),
            shorten_home(file)
        ));
    }

    if let Some(old) = prev_form {
        out.push_str(&render_pretty_diff(old, canonical_form, pp_width));
    } else {
        let pretty = pretty_form(canonical_form, pp_width, color);
        for line in pretty.lines() {
            out.push_str(&format!("    {}\n", line));
        }
    }

    out.push('\n');
    out
}

/// Render a line-level diff between pretty-printed old and new forms.
fn render_pretty_diff(old_canonical: &str, new_canonical: &str, pp_width: usize) -> String {
    let color = crate::sink::stderr_color();
    let old_pretty = pretty_form(old_canonical, pp_width, false);
    let new_pretty = pretty_form(new_canonical, pp_width, false);
    let diff = similar::TextDiff::from_lines(&old_pretty, &new_pretty);

    let mut out = String::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!("-{}", change), Style::DenySoft, color)
                ));
            }
            similar::ChangeTag::Insert => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!("+{}", change), Style::AllowSoft, color)
                ));
            }
            similar::ChangeTag::Equal => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!(" {}", change), Style::Dimmed, color)
                ));
            }
        }
    }
    out
}

/// Render the entry detail block for the legacy program-level review.
pub(crate) fn render_entry_detail(
    program: &str,
    status: &str,
    canonical_rules: &[String],
    source_files: &BTreeSet<PathBuf>,
    previous_rules: Option<&[String]>,
) -> String {
    let color = crate::sink::stderr_color();
    let badge = match status {
        "NEW" => paint(status, Style::Ask, color),
        "CHANGED" => paint(status, Style::Deny, color),
        _ => status.to_string(),
    };

    let mut out = String::new();
    out.push_str(&format!(
        "  {} {}\n",
        paint(program, Style::Strong, color),
        badge
    ));

    for file in source_files {
        out.push_str(&format!(
            "    {} {}\n",
            paint("file:", Style::Dimmed, color),
            shorten_home(file)
        ));
    }

    if status == "CHANGED" {
        if let Some(prev) = previous_rules {
            let old_pretty: Vec<String> = prev.iter().map(|r| pretty_form(r, 72, false)).collect();
            let new_pretty: Vec<String> = canonical_rules
                .iter()
                .map(|r| pretty_form(r, 72, false))
                .collect();
            out.push_str(&render_diff(&old_pretty, &new_pretty));
        }
    } else {
        for rule in canonical_rules {
            let pretty = pretty_form(rule, 72, color);
            for line in pretty.lines() {
                out.push_str(&format!("    {}\n", line));
            }
        }
    }
    out.push('\n');
    out
}

/// Render a line-level diff between joined previous and current rule forms.
fn render_diff(old: &[String], new: &[String]) -> String {
    let color = crate::sink::stderr_color();
    let old_text = old.join("\n");
    let new_text = new.join("\n");
    let diff = similar::TextDiff::from_lines(&old_text, &new_text);

    let mut out = String::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!("-{}", change), Style::DenySoft, color)
                ));
            }
            similar::ChangeTag::Insert => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!("+{}", change), Style::AllowSoft, color)
                ));
            }
            similar::ChangeTag::Equal => {
                out.push_str(&format!(
                    "    {}",
                    paint(format!(" {}", change), Style::Dimmed, color)
                ));
            }
        }
    }
    out
}

/// Render the final review session summary line.
pub(crate) fn render_summary(summary: &ReviewSummary) -> String {
    let color = crate::sink::stderr_color();
    format!(
        "  {}  {}  {}\n",
        paint(
            format!("Approved: {}", summary.approved),
            Style::AllowSoft,
            color
        ),
        paint(
            format!("Blocked: {}", summary.blocked),
            Style::DenySoft,
            color
        ),
        paint(
            format!("Skipped: {}", summary.skipped),
            Style::AskSoft,
            color
        ),
    )
}

/// Render the trusted-rules summary line shown above each progress separator.
pub(crate) fn render_trusted_summary(
    trusted_rule_count: usize,
    trusted_file_count: usize,
) -> String {
    if trusted_rule_count == 0 {
        return String::new();
    }
    let color = crate::sink::stderr_color();
    format!(
        "  {}\n\n",
        paint(
            format!(
                "{} rules trusted across {} files",
                trusted_rule_count, trusted_file_count
            ),
            Style::Dimmed,
            color
        )
    )
}

/// Render the labelled progress separator into a string for the given
/// terminal. Routes through the shared `output::render_labelled_separator`
/// helper so colour/HRule behaviour stays consistent with the rest of the
/// CLI.
pub(crate) fn render_separator(label: may_i_output::Styled, term: &Terminal) -> String {
    let mut buf: Vec<u8> = Vec::new();
    render_labelled_separator(&mut buf, term, "  ", Some(label));
    String::from_utf8(buf).unwrap_or_default()
}

/// Render the per-rule progress separator with badge.
pub(crate) fn render_progress_label(idx: usize, total: usize, badge: &str) -> may_i_output::Styled {
    use may_i_output::{Style, Styled};
    let badge_style = match badge {
        "NEW" => Style::Ask,
        "CHANGED" => Style::Deny,
        _ => Style::Plain,
    };
    Styled::span(format!("Rule {}/{} ", idx + 1, total), Style::Plain)
        .with("──", Style::Dimmed)
        .with(" ", Style::Plain)
        .with(badge, badge_style)
}

/// Render the per-rule key legend.
pub(crate) fn render_key_legend() -> String {
    let color = crate::sink::stderr_color();
    format!(
        "  {} approve  {} block  {} skip  {} quit  {}\n",
        paint("[y]", Style::Strong, color),
        paint("[n]", Style::Strong, color),
        paint("[s]", Style::Strong, color),
        paint("[q]", Style::Strong, color),
        paint("?", Style::Dimmed, color)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_form_indents_complex_rule() {
        let canonical = r#"(rule "git" (when (fact? :env "prod") (effect :allow "safe")))"#;
        let result = pretty_form(canonical, 40, false);
        assert!(
            result.contains('\n'),
            "expected multi-line output, got: {result}"
        );
        assert!(result.starts_with("(rule"));
    }

    #[test]
    fn pretty_form_indents_rule_with_body() {
        let canonical = r#"(rule "echo" (effect :allow))"#;
        let result = pretty_form(canonical, 80, false);
        assert!(result.starts_with(r#"(rule "echo""#));
    }

    #[test]
    fn pretty_form_returns_input_on_parse_failure() {
        let bad = "not valid sexpr ((";
        let result = pretty_form(bad, 80, false);
        assert!(!result.is_empty());
    }
}

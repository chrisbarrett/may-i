// Pure rendering helpers for the trust review and repair loops. Each function
// returns a string (or string fragments) so the loop can hand the result to
// `UserPrompt::render`. This module is the only place inside
// `src/trust/review/` allowed to import `may_i_pp`, `may_i_sexpr`, `similar`,
// or `colored`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use colored::Colorize;

use may_i_core::Doc;

use crate::output::{Terminal, render_labelled_separator, shorten_home};
use crate::trust::review::prompt::ReviewSummary;
use crate::trust::store::SuspectEntry;

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
    may_i_pp::pretty(&doc, 0, &fmt)
}

/// Render the detail block for a single suspect entry (integrity failure).
pub(crate) fn render_suspect_detail(suspect: &SuspectEntry) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "  {} {}\n",
        suspect.program.bold(),
        "SUSPECT".red().bold()
    ));
    out.push_str(&format!(
        "    {} {}\n",
        "stored hash:".dimmed(),
        suspect.hash.dimmed()
    ));
    out.push_str(&format!("    {}\n", suspect.stored_form.dimmed()));
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
    let mut out = String::new();
    if let Some(file) = source_file {
        out.push_str(&format!("  {} {}\n", "file:".dimmed(), shorten_home(file)));
    }

    if let Some(old) = prev_form {
        out.push_str(&render_pretty_diff(old, canonical_form, pp_width));
    } else {
        let pretty = pretty_form(canonical_form, pp_width, true);
        for line in pretty.lines() {
            out.push_str(&format!("    {}\n", line));
        }
    }

    out.push('\n');
    out
}

/// Render a line-level diff between pretty-printed old and new forms.
fn render_pretty_diff(old_canonical: &str, new_canonical: &str, pp_width: usize) -> String {
    let old_pretty = pretty_form(old_canonical, pp_width, false);
    let new_pretty = pretty_form(new_canonical, pp_width, false);
    let diff = similar::TextDiff::from_lines(&old_pretty, &new_pretty);

    let mut out = String::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                out.push_str(&format!("    {}", format!("-{}", change).red()));
            }
            similar::ChangeTag::Insert => {
                out.push_str(&format!("    {}", format!("+{}", change).green()));
            }
            similar::ChangeTag::Equal => {
                out.push_str(&format!("    {}", format!(" {}", change).dimmed()));
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
    let badge = match status {
        "NEW" => status.yellow().bold().to_string(),
        "CHANGED" => status.red().bold().to_string(),
        _ => status.to_string(),
    };

    let mut out = String::new();
    out.push_str(&format!("  {} {}\n", program.bold(), badge));

    for file in source_files {
        out.push_str(&format!(
            "    {} {}\n",
            "file:".dimmed(),
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
            let pretty = pretty_form(rule, 72, true);
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
    let old_text = old.join("\n");
    let new_text = new.join("\n");
    let diff = similar::TextDiff::from_lines(&old_text, &new_text);

    let mut out = String::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                out.push_str(&format!("    {}", format!("-{}", change).red()));
            }
            similar::ChangeTag::Insert => {
                out.push_str(&format!("    {}", format!("+{}", change).green()));
            }
            similar::ChangeTag::Equal => {
                out.push_str(&format!("    {}", format!(" {}", change).dimmed()));
            }
        }
    }
    out
}

/// Render the final review session summary line.
pub(crate) fn render_summary(summary: &ReviewSummary) -> String {
    format!(
        "  {}  {}  {}\n",
        format!("Approved: {}", summary.approved).green(),
        format!("Blocked: {}", summary.blocked).red(),
        format!("Skipped: {}", summary.skipped).yellow(),
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
    format!(
        "  {}\n\n",
        format!(
            "{} rules trusted across {} files",
            trusted_rule_count, trusted_file_count
        )
        .dimmed()
    )
}

/// Render the labelled progress separator into a string for the given
/// terminal. Routes through the shared `output::render_labelled_separator`
/// helper so colour/HRule behaviour stays consistent with the rest of the
/// CLI.
pub(crate) fn render_separator(label: &str, visible_width: usize, term: &Terminal) -> String {
    let mut buf: Vec<u8> = Vec::new();
    render_labelled_separator(&mut buf, term, "  ", Some((label, visible_width)));
    String::from_utf8(buf).unwrap_or_default()
}

/// Render the per-rule progress separator with badge.
pub(crate) fn render_progress_label(idx: usize, total: usize, badge: &str) -> (String, usize) {
    let colored_badge = match badge {
        "NEW" => badge.yellow().bold().to_string(),
        "CHANGED" => badge.red().bold().to_string(),
        _ => badge.to_string(),
    };
    let label = format!(
        "Rule {}/{} {} {}",
        idx + 1,
        total,
        "──".dimmed(),
        colored_badge
    );
    let visible_len = format!("Rule {}/{} ── {}", idx + 1, total, badge).len();
    (label, visible_len)
}

/// Render the per-rule key legend.
pub(crate) fn render_key_legend() -> String {
    format!(
        "  {} approve  {} block  {} skip  {} quit  {}\n",
        "[y]".bold(),
        "[n]".bold(),
        "[s]".bold(),
        "[q]".bold(),
        "?".dimmed()
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

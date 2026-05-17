// Interactive review for trust operations — integrity repair, per-rule review,
// and per-program batch approval. All flows consume `TrustCatalog` for the
// per-rule join; persistence is a separate `save` call after the catalog
// mutates.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use colored::Colorize;

use may_i_core::Doc;

use crate::output::shorten_home;
use crate::trust::store::{SuspectEntry, TrustStore};
use crate::trust::view::{TrustCatalog, TrustState, TrustView};

/// Whether the session is interactive (TTY on stdin, no --json).
pub fn is_interactive(json_mode: bool) -> bool {
    !json_mode && std::io::stdin().is_terminal()
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

/// Pretty-print a canonical form string using the pp crate's indentation engine.
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

/// Summary of an interactive review session.
pub struct ReviewSummary {
    pub approved: usize,
    pub blocked: usize,
    pub skipped: usize,
}

/// Display detail for a suspect entry (integrity failure).
fn render_suspect_detail(w: &mut impl Write, suspect: &SuspectEntry) {
    let _ = writeln!(w, "  {} {}", suspect.program.bold(), "SUSPECT".red().bold());
    let _ = writeln!(
        w,
        "    {} {}",
        "stored hash:".dimmed(),
        suspect.hash.dimmed()
    );
    let _ = writeln!(w, "    {}", suspect.stored_form.dimmed());
    let _ = writeln!(w);
}

/// Run integrity repair for suspect entries. Returns true if store was modified.
///
/// Operates on the raw store rather than the catalog: integrity repair happens
/// before the join, so the post-repair store can produce a coherent catalog.
pub fn repair_integrity(
    store: &mut TrustStore,
    suspects: &[SuspectEntry],
    interactive: bool,
) -> miette::Result<bool> {
    if suspects.is_empty() {
        return Ok(false);
    }

    if !interactive {
        let names: Vec<&str> = suspects.iter().map(|s| s.program.as_str()).collect();
        if let Some(store_path) = crate::trust::store::default_trust_store_path() {
            let term = crate::output::Terminal::detect();
            let note = crate::trust::advisory::build_integrity_layout(&store_path, Some(&names));
            crate::output::write_layout(&mut std::io::stderr(), &note, &term);
        }
        return Ok(false);
    }

    eprintln!(
        "\n{}",
        "Trust store integrity check found suspect entries:"
            .yellow()
            .bold()
    );
    eprintln!(
        "{}",
        "Stored canonical forms do not match their hashes.\n".dimmed()
    );

    let mut modified = false;
    for suspect in suspects {
        render_suspect_detail(&mut std::io::stderr(), suspect);

        let choice = dialoguer::Select::new()
            .with_prompt(format!("  {} → action", suspect.program))
            .items(&[
                "Re-approve (accept stored forms, recompute hash)",
                "Drop (remove entry)",
            ])
            .default(0)
            .interact()
            .map_err(|e| miette::miette!("prompt failed: {e}"))?;

        match choice {
            0 => {
                store.reapprove(&suspect.program);
                eprintln!("  {} re-approved", suspect.program.green());
            }
            1 => {
                store.drop_entry(&suspect.program);
                eprintln!("  {} dropped", suspect.program.red());
            }
            _ => unreachable!(),
        }
        modified = true;
    }

    Ok(modified)
}

/// Interactive per-rule review with single-key `y/n/s/q` keybindings.
///
/// Walks through each pending rule in the catalog, displaying its form and
/// prompting for action. Returns the list of approved program names (for
/// reporting). The catalog mirrors mutations into its backing store; callers
/// persist via `catalog.save(path)`.
pub fn interactive_review(
    catalog: &mut TrustCatalog,
) -> miette::Result<(Vec<String>, ReviewSummary)> {
    let mut term = console::Term::stderr();
    let mut approved_programs = Vec::new();
    let mut summary = ReviewSummary {
        approved: 0,
        blocked: 0,
        skipped: 0,
    };

    // Snapshot pending views (hashes + canonical forms) so we can mutate the
    // catalog inside the loop.
    let pending: Vec<(String, String, String, Option<std::path::PathBuf>, usize)> = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Pending)
        .map(|v| {
            (
                v.hash().to_string(),
                v.program().to_string(),
                v.canonical_form().to_string(),
                v.source_file().map(|p| p.to_path_buf()),
                v.position(),
            )
        })
        .collect();
    let total_pending = pending.len();

    // Initial counts (trusted = currently approved).
    let mut trusted_rule_count = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Approved)
        .count();
    let mut trusted_files: std::collections::BTreeSet<std::path::PathBuf> = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Approved)
        .filter_map(|v| v.source_file().map(|p| p.to_path_buf()))
        .collect();
    let mut trusted_file_count = trusted_files.len();

    let term_width = term.size().1 as usize;
    let pp_width = term_width.saturating_sub(4).max(40);

    for (idx, (hash, program, canonical_form, source_file, position)) in pending.iter().enumerate()
    {
        let (badge, prev_form) = detect_change(catalog.store(), program, canonical_form, *position);

        // Clear screen and show context.
        let _ = term.clear_screen();

        // Trusted summary line.
        if trusted_rule_count > 0 {
            let _ = writeln!(
                term,
                "  {}",
                format!(
                    "{} rules trusted across {} files",
                    trusted_rule_count, trusted_file_count
                )
                .dimmed()
            );
            let _ = writeln!(term);
        }

        // Progress HRule separator.
        let colored_badge = match badge {
            "NEW" => badge.yellow().bold().to_string(),
            "CHANGED" => badge.red().bold().to_string(),
            _ => badge.to_string(),
        };
        let progress_label = format!(
            "Rule {}/{} {} {}",
            idx + 1,
            total_pending,
            "──".dimmed(),
            colored_badge
        );
        let visible_len = format!("Rule {}/{} ── {}", idx + 1, total_pending, badge).len();
        let out_term = crate::output::Terminal::detect();
        crate::output::render_labelled_separator(
            &mut std::io::stderr(),
            &out_term,
            "  ",
            Some((&progress_label, visible_len)),
        );
        let _ = writeln!(term);

        render_rule_detail(
            &mut term,
            source_file.as_deref(),
            canonical_form,
            prev_form.as_deref(),
            pp_width,
        )?;

        let _ = writeln!(
            term,
            "  {} approve  {} block  {} skip  {} quit  {}",
            "[y]".bold(),
            "[n]".bold(),
            "[s]".bold(),
            "[q]".bold(),
            "?".dimmed()
        );

        loop {
            let ch = term
                .read_char()
                .map_err(|e| miette::miette!("read key failed: {e}"))?;
            match ch {
                'y' | 'Y' => {
                    catalog.set_state(hash, TrustState::Approved);
                    approved_programs.push(program.clone());
                    summary.approved += 1;
                    trusted_rule_count += 1;
                    if let Some(f) = source_file
                        && trusted_files.insert(f.clone())
                    {
                        trusted_file_count += 1;
                    }
                    break;
                }
                'n' | 'N' => {
                    catalog.set_state(hash, TrustState::Blocked);
                    summary.blocked += 1;
                    break;
                }
                's' | 'S' => {
                    summary.skipped += 1;
                    break;
                }
                'q' | 'Q' => {
                    let _ = term.clear_screen();
                    print_summary(&mut term, &summary);
                    return Ok((approved_programs, summary));
                }
                _ => {
                    // Invalid key — ignore, wait for valid input.
                }
            }
        }
    }

    let _ = term.clear_screen();
    print_summary(&mut term, &summary);
    Ok((approved_programs, summary))
}

/// Detect whether a rule is NEW or CHANGED relative to stored rules.
fn detect_change(
    store: &TrustStore,
    program: &str,
    canonical_form: &str,
    position: usize,
) -> (&'static str, Option<String>) {
    let stored_forms: Vec<String> = store.previous_rules(program).unwrap_or_default();

    if stored_forms.is_empty() {
        return ("NEW", None);
    }

    if let Some(old_form) = stored_forms.get(position)
        && *old_form != canonical_form
    {
        return ("CHANGED", Some(old_form.clone()));
    }

    ("NEW", None)
}

/// Render a single rule for review using pretty-printed forms.
fn render_rule_detail(
    term: &mut console::Term,
    source_file: Option<&std::path::Path>,
    canonical_form: &str,
    prev_form: Option<&str>,
    pp_width: usize,
) -> miette::Result<()> {
    if let Some(file) = source_file {
        let _ = writeln!(term, "  {} {}", "file:".dimmed(), shorten_home(file));
    }

    if let Some(old) = prev_form {
        render_pretty_diff(term, old, canonical_form, pp_width);
    } else {
        let pretty = pretty_form(canonical_form, pp_width, true);
        for line in pretty.lines() {
            let _ = writeln!(term, "    {}", line);
        }
    }

    let _ = writeln!(term);
    Ok(())
}

/// Render a line-level diff between pretty-printed old and new forms.
fn render_pretty_diff(
    w: &mut impl Write,
    old_canonical: &str,
    new_canonical: &str,
    pp_width: usize,
) {
    let old_pretty = pretty_form(old_canonical, pp_width, false);
    let new_pretty = pretty_form(new_canonical, pp_width, false);
    let diff = similar::TextDiff::from_lines(&old_pretty, &new_pretty);

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                let _ = write!(w, "    {}", format!("-{}", change).red());
            }
            similar::ChangeTag::Insert => {
                let _ = write!(w, "    {}", format!("+{}", change).green());
            }
            similar::ChangeTag::Equal => {
                let _ = write!(w, "    {}", format!(" {}", change).dimmed());
            }
        }
    }
}

fn print_summary(term: &mut console::Term, summary: &ReviewSummary) {
    let _ = writeln!(
        term,
        "  {}  {}  {}",
        format!("Approved: {}", summary.approved).green(),
        format!("Blocked: {}", summary.blocked).red(),
        format!("Skipped: {}", summary.skipped).yellow(),
    );
}

/// Legacy program-level interactive approval over the catalog.
///
/// `programs` is the lexically-ordered set of programs to confirm; each
/// confirmed program transitions every one of its pending or blocked views to
/// Approved. Returns the program names that were approved.
pub fn interactive_approve_programs(
    catalog: &mut TrustCatalog,
    programs: &[String],
) -> miette::Result<Vec<String>> {
    let mut approved = Vec::new();

    for program in programs {
        // Snapshot per-program views before mutating.
        let views_for_program: Vec<(String, String, Option<std::path::PathBuf>, TrustState)> =
            catalog
                .iter()
                .filter(|v| v.program() == program.as_str())
                .map(|v| {
                    (
                        v.hash().to_string(),
                        v.canonical_form().to_string(),
                        v.source_file().map(|p| p.to_path_buf()),
                        v.state(),
                    )
                })
                .collect();

        if views_for_program.is_empty()
            || views_for_program
                .iter()
                .all(|(_, _, _, s)| *s == TrustState::Approved)
        {
            continue;
        }

        let any_with_prior = catalog.store().previous_rules(program).is_some();
        let badge = if any_with_prior { "CHANGED" } else { "NEW" };
        let prev = if badge == "CHANGED" {
            catalog.store().previous_rules(program)
        } else {
            None
        };

        let canonical_rules: Vec<String> = views_for_program
            .iter()
            .map(|(_, form, _, _)| form.clone())
            .collect();
        let source_files: std::collections::BTreeSet<std::path::PathBuf> = views_for_program
            .iter()
            .filter_map(|(_, _, sf, _)| sf.clone())
            .collect();

        render_entry_detail(
            &mut std::io::stderr(),
            program,
            badge,
            &canonical_rules,
            &source_files,
            prev.as_deref(),
        );

        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("  Approve {}?", program))
            .default(true)
            .interact()
            .map_err(|e| miette::miette!("prompt failed: {e}"))?;

        if confirm {
            for (hash, _, _, _) in &views_for_program {
                catalog.set_state(hash, TrustState::Approved);
            }
            approved.push(program.clone());
            eprintln!("  {} approved\n", program.green());
        } else {
            eprintln!("  {} skipped\n", program.yellow());
        }
    }

    Ok(approved)
}

/// Display entry detail for legacy program-level review.
fn render_entry_detail(
    w: &mut impl Write,
    program: &str,
    status: &str,
    canonical_rules: &[String],
    source_files: &std::collections::BTreeSet<std::path::PathBuf>,
    previous_rules: Option<&[String]>,
) {
    let badge = match status {
        "NEW" => status.yellow().bold().to_string(),
        "CHANGED" => status.red().bold().to_string(),
        _ => status.to_string(),
    };

    let _ = writeln!(w, "  {} {}", program.bold(), badge);

    for file in source_files {
        let _ = writeln!(w, "    {} {}", "file:".dimmed(), shorten_home(file));
    }

    if status == "CHANGED" {
        if let Some(prev) = previous_rules {
            let old_pretty: Vec<String> = prev.iter().map(|r| pretty_form(r, 72, false)).collect();
            let new_pretty: Vec<String> = canonical_rules
                .iter()
                .map(|r| pretty_form(r, 72, false))
                .collect();
            render_diff(w, &old_pretty, &new_pretty);
        }
    } else {
        for rule in canonical_rules {
            let pretty = pretty_form(rule, 72, true);
            for line in pretty.lines() {
                let _ = writeln!(w, "    {}", line);
            }
        }
    }
    let _ = writeln!(w);
}

/// Render a line-level diff between previous and current rule forms.
fn render_diff(w: &mut impl Write, old: &[String], new: &[String]) {
    let old_text = old.join("\n");
    let new_text = new.join("\n");
    let diff = similar::TextDiff::from_lines(&old_text, &new_text);

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                let _ = write!(w, "    {}", format!("-{}", change).red());
            }
            similar::ChangeTag::Insert => {
                let _ = write!(w, "    {}", format!("+{}", change).green());
            }
            similar::ChangeTag::Equal => {
                let _ = write!(w, "    {}", format!(" {}", change).dimmed());
            }
        }
    }
}

/// Non-interactive batch approval — approve all pending rules in the catalog
/// without prompting. Returns the deduplicated, sorted list of program names
/// that gained at least one new approval.
pub fn batch_approve(catalog: &mut TrustCatalog) -> Vec<String> {
    let to_approve: Vec<(String, String)> = catalog
        .iter()
        .filter(|v| v.state() != TrustState::Approved)
        .map(|v| (v.hash().to_string(), v.program().to_string()))
        .collect();
    let mut approved: Vec<String> = to_approve.iter().map(|(_, p)| p.clone()).collect();
    for (hash, _) in &to_approve {
        catalog.set_state(hash, TrustState::Approved);
    }
    approved.sort();
    approved.dedup();
    approved
}

/// Collect the lexically-ordered list of programs that have at least one
/// pending or blocked view in the catalog.
pub fn pending_programs(catalog: &TrustCatalog) -> Vec<String> {
    let groups: BTreeMap<&str, Vec<&TrustView>> = catalog.group_by_program();
    groups
        .into_iter()
        .filter_map(|(program, views)| {
            if views.iter().any(|v| v.state() != TrustState::Approved) {
                Some(program.to_string())
            } else {
                None
            }
        })
        .collect()
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

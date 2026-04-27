// Interactive review for trust operations — integrity repair and per-rule review.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use colored::Colorize;
use may_i_engine::trust::{ProgramMeta, RuleMeta, TrustHashes};

use may_i_core::Doc;

use crate::output::shorten_home;
use crate::trust_store::{SuspectEntry, TrustCheck, TrustStatus, TrustStore};

/// Whether the session is interactive (TTY on stdin, no --json).
pub fn is_interactive(json_mode: bool) -> bool {
    !json_mode && std::io::stdin().is_terminal()
}

/// Convert a parsed s-expression into a `Doc` tree for pretty-printing.
fn doc_from_sexpr(sexpr: &may_i_sexpr::Sexpr) -> Doc {
    match sexpr {
        may_i_sexpr::Sexpr::Keyword(s, _) | may_i_sexpr::Sexpr::Symbol(s, _) => {
            Doc::atom(s.clone())
        }
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
        if let Some(store_path) = crate::trust_store::default_trust_store_path() {
            let term = crate::output::Terminal::detect();
            let note = crate::output::trust_integrity_note(&store_path, Some(&names));
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
/// Walks through each pending rule, displaying its form and prompting for action.
/// Returns list of approved program names (for reporting).
pub fn interactive_review(
    store: &mut TrustStore,
    hashes: &TrustHashes,
) -> miette::Result<(Vec<String>, ReviewSummary)> {
    let mut term = console::Term::stderr();
    let mut approved_programs = Vec::new();
    let mut summary = ReviewSummary {
        approved: 0,
        blocked: 0,
        skipped: 0,
    };

    // Group rules by program for change detection.
    let mut by_program: BTreeMap<&str, Vec<&RuleMeta>> = BTreeMap::new();
    for rule in &hashes.rules {
        by_program.entry(&rule.program).or_default().push(rule);
    }

    // Count trusted rules and distinct source files for the summary line.
    let trusted_count = hashes
        .rules
        .iter()
        .filter(|r| store.check_rule(&r.hash) == TrustCheck::Approved)
        .count();
    let mut trusted_files: std::collections::BTreeSet<_> = hashes
        .rules
        .iter()
        .filter(|r| store.check_rule(&r.hash) == TrustCheck::Approved)
        .filter_map(|r| r.source_file.as_ref())
        .collect();
    let mut trusted_rule_count = trusted_count;
    let mut trusted_file_count = trusted_files.len();

    // Collect pending rules for progress tracking.
    let pending: Vec<&RuleMeta> = hashes
        .rules
        .iter()
        .filter(|r| {
            let check = store.check_rule(&r.hash);
            check != TrustCheck::Approved && check != TrustCheck::Blocked
        })
        .collect();
    let total_pending = pending.len();

    let term_width = term.size().1 as usize;
    let pp_width = term_width.saturating_sub(4).max(40);

    for (idx, rule_meta) in pending.iter().enumerate() {
        let (badge, prev_form) = detect_change(store, rule_meta, &by_program);

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
        let hrule = may_i_layout::Layout::HRule(Some(may_i_layout::HRuleLabel {
            text: progress_label,
            visible_width: visible_len,
        }));
        let indented = may_i_layout::Layout::Indent(2, Box::new(hrule));
        may_i_layout::write_layout(&mut std::io::stderr(), &indented, &out_term);
        let _ = writeln!(term);

        render_rule_detail(&mut term, rule_meta, prev_form.as_deref(), pp_width)?;

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
                    store.approve_rule(
                        rule_meta.hash.clone(),
                        rule_meta.program.clone(),
                        rule_meta.canonical_form.clone(),
                    );
                    approved_programs.push(rule_meta.program.clone());
                    summary.approved += 1;
                    trusted_rule_count += 1;
                    if let Some(f) = &rule_meta.source_file
                        && trusted_files.insert(f)
                    {
                        trusted_file_count += 1;
                    }
                    break;
                }
                'n' | 'N' => {
                    store.block_rule(
                        rule_meta.hash.clone(),
                        rule_meta.program.clone(),
                        rule_meta.canonical_form.clone(),
                    );
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
    rule_meta: &RuleMeta,
    _by_program: &BTreeMap<&str, Vec<&RuleMeta>>,
) -> (&'static str, Option<String>) {
    // Look at stored rules for the same program, compare by position.
    let stored_forms: Vec<String> = store.previous_rules(&rule_meta.program).unwrap_or_default();

    if stored_forms.is_empty() {
        return ("NEW", None);
    }

    // Check if there's a stored rule at the same position.
    if let Some(old_form) = stored_forms.get(rule_meta.position)
        && *old_form != rule_meta.canonical_form
    {
        return ("CHANGED", Some(old_form.clone()));
    }

    // Position beyond stored count = new rule.
    ("NEW", None)
}

/// Render a single rule for review using pretty-printed forms.
fn render_rule_detail(
    term: &mut console::Term,
    rule_meta: &RuleMeta,
    prev_form: Option<&str>,
    pp_width: usize,
) -> miette::Result<()> {
    if let Some(file) = &rule_meta.source_file {
        let _ = writeln!(term, "  {} {}", "file:".dimmed(), shorten_home(file));
    }

    if let Some(old) = prev_form {
        render_pretty_diff(term, old, &rule_meta.canonical_form, pp_width);
    } else {
        let pretty = pretty_form(&rule_meta.canonical_form, pp_width, true);
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

/// Legacy program-level interactive approval. Returns list of approved programs.
pub fn interactive_approve(
    store: &mut TrustStore,
    programs: &[(&str, &ProgramMeta, TrustStatus)],
) -> miette::Result<Vec<String>> {
    let mut approved = Vec::new();

    for &(program, meta, ref status) in programs {
        let status_str = match status {
            TrustStatus::New => "NEW",
            TrustStatus::Changed => "CHANGED",
            TrustStatus::Trusted => continue,
        };

        let prev = if *status == TrustStatus::Changed {
            store.previous_rules(program)
        } else {
            None
        };
        render_entry_detail(
            &mut std::io::stderr(),
            program,
            status_str,
            meta,
            prev.as_deref(),
        );

        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("  Approve {}?", program))
            .default(true)
            .interact()
            .map_err(|e| miette::miette!("prompt failed: {e}"))?;

        if confirm {
            store.approve(
                program.to_string(),
                meta.hash.clone(),
                meta.canonical_rules.clone(),
            );
            approved.push(program.to_string());
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
    meta: &ProgramMeta,
    previous_rules: Option<&[String]>,
) {
    let badge = match status {
        "NEW" => status.yellow().bold().to_string(),
        "CHANGED" => status.red().bold().to_string(),
        _ => status.to_string(),
    };

    let _ = writeln!(w, "  {} {}", program.bold(), badge);

    for file in &meta.source_files {
        let _ = writeln!(w, "    {} {}", "file:".dimmed(), shorten_home(file));
    }

    if status == "CHANGED" {
        if let Some(prev) = previous_rules {
            let old_pretty: Vec<String> = prev.iter().map(|r| pretty_form(r, 72, false)).collect();
            let new_pretty: Vec<String> = meta
                .canonical_rules
                .iter()
                .map(|r| pretty_form(r, 72, false))
                .collect();
            render_diff(w, &old_pretty, &new_pretty);
        }
    } else {
        for rule in &meta.canonical_rules {
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

/// Batch (non-interactive) approval — approve all pending rules without prompting.
pub fn batch_approve(
    store: &mut TrustStore,
    hashes: &TrustHashes,
    _programs: &BTreeMap<String, ProgramMeta>,
) -> Vec<String> {
    let mut approved = Vec::new();
    for rule_meta in &hashes.rules {
        if store.check_rule(&rule_meta.hash) != TrustCheck::Approved {
            store.approve_rule(
                rule_meta.hash.clone(),
                rule_meta.program.clone(),
                rule_meta.canonical_form.clone(),
            );
            approved.push(rule_meta.program.clone());
        }
    }
    // Deduplicate program names.
    approved.sort();
    approved.dedup();
    approved
}

/// Collect pending (NEW/CHANGED) entries from programs view against the store.
pub fn pending_entries<'a>(
    store: &TrustStore,
    programs: &'a BTreeMap<String, ProgramMeta>,
) -> Vec<(&'a str, &'a ProgramMeta, TrustStatus)> {
    programs
        .iter()
        .filter_map(|(program, meta)| {
            let status = store.check(program, &meta.hash);
            match status {
                TrustStatus::Trusted => None,
                _ => Some((program.as_str(), meta, status)),
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
        // Should produce multi-line output with indentation.
        assert!(
            result.contains('\n'),
            "expected multi-line output, got: {result}"
        );
        assert!(result.starts_with("(rule"));
    }

    #[test]
    fn pretty_form_indents_rule_with_body() {
        // `rule` has indent spec N=1, so command is special and body indents +2.
        let canonical = r#"(rule "echo" (effect :allow))"#;
        let result = pretty_form(canonical, 80, false);
        assert!(result.starts_with(r#"(rule "echo""#));
    }

    #[test]
    fn pretty_form_returns_input_on_parse_failure() {
        let bad = "not valid sexpr ((";
        let result = pretty_form(bad, 80, false);
        // Should not panic; returns something reasonable.
        assert!(!result.is_empty());
    }
}

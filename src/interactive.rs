// Interactive review for trust operations — integrity repair and per-rule review.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use colored::Colorize;
use may_i_engine::trust::{ProgramMeta, RuleMeta, TrustHashes};

use crate::output::shorten_home;
use crate::trust_store::{SuspectEntry, TrustCheck, TrustStatus, TrustStore};

/// Whether the session is interactive (TTY on stdin, no --json).
pub fn is_interactive(json_mode: bool) -> bool {
    !json_mode && std::io::stdin().is_terminal()
}

/// Summary of an interactive review session.
pub struct ReviewSummary {
    pub approved: usize,
    pub ignored: usize,
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
        ignored: 0,
        skipped: 0,
    };

    // Group rules by program for change detection.
    let mut by_program: BTreeMap<&str, Vec<&RuleMeta>> = BTreeMap::new();
    for rule in &hashes.rules {
        by_program.entry(&rule.program).or_default().push(rule);
    }

    for rule_meta in &hashes.rules {
        let check = store.check_rule(&rule_meta.hash);
        if check == TrustCheck::Approved || check == TrustCheck::Ignored {
            continue; // Already reviewed.
        }

        // Detect if this is a CHANGED rule by checking if there's a stored rule
        // at the same position for the same program.
        let (badge, prev_form) = detect_change(store, rule_meta, &by_program);

        render_rule_detail(&mut term, rule_meta, badge, prev_form.as_deref())?;

        let _ = writeln!(
            term,
            "  {} approve  {} ignore  {} skip  {} quit  {}",
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
                    let _ = writeln!(term, "  {} {}\n", "→".dimmed(), "approved".green());
                    break;
                }
                'n' | 'N' => {
                    store.ignore_rule(
                        rule_meta.hash.clone(),
                        rule_meta.program.clone(),
                        rule_meta.canonical_form.clone(),
                    );
                    summary.ignored += 1;
                    let _ = writeln!(term, "  {} {}\n", "→".dimmed(), "ignored".red());
                    break;
                }
                's' | 'S' => {
                    summary.skipped += 1;
                    let _ = writeln!(term, "  {} {}\n", "→".dimmed(), "skipped".yellow());
                    break;
                }
                'q' | 'Q' => {
                    let _ = writeln!(term, "  {} {}\n", "→".dimmed(), "quit".dimmed());
                    print_summary(&mut term, &summary);
                    return Ok((approved_programs, summary));
                }
                _ => {
                    // Invalid key — ignore, wait for valid input.
                }
            }
        }
    }

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

/// Render a single rule for review.
fn render_rule_detail(
    term: &mut console::Term,
    rule_meta: &RuleMeta,
    badge: &str,
    prev_form: Option<&str>,
) -> miette::Result<()> {
    let colored_badge = match badge {
        "NEW" => badge.yellow().bold().to_string(),
        "CHANGED" => badge.red().bold().to_string(),
        _ => badge.to_string(),
    };

    let _ = writeln!(
        term,
        "  {} {}",
        rule_meta.canonical_form.dimmed(),
        colored_badge
    );

    if let Some(file) = &rule_meta.source_file {
        let _ = writeln!(term, "    {} {}", "file:".dimmed(), shorten_home(file));
    }

    if let Some(old) = prev_form {
        let _ = writeln!(term, "    {}", format!("-{}", old).red());
        let _ = writeln!(
            term,
            "    {}",
            format!("+{}", rule_meta.canonical_form).green()
        );
    }

    let _ = writeln!(term);
    Ok(())
}

fn print_summary(term: &mut console::Term, summary: &ReviewSummary) {
    let _ = writeln!(
        term,
        "  {}  {}  {}",
        format!("Approved: {}", summary.approved).green(),
        format!("Ignored: {}", summary.ignored).red(),
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
            render_diff(w, prev, &meta.canonical_rules);
        }
    } else {
        for rule in &meta.canonical_rules {
            let _ = writeln!(w, "    {}", rule.dimmed());
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

// Interactive review for trust operations — integrity repair and approval prompts.

use std::io::{IsTerminal, Write};

use colored::Colorize;
use may_i_engine::trust::{ProgramMeta, TrustHashes};

use crate::output::shorten_home;
use crate::trust_store::{SuspectEntry, TrustStatus, TrustStore};

/// Whether the session is interactive (TTY on stdin, no --json).
pub fn is_interactive(json_mode: bool) -> bool {
    !json_mode && std::io::stdin().is_terminal()
}

/// Display entry detail: program name, status badge, source files, canonical rule forms.
/// For CHANGED entries, show diff against previous forms.
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

/// Display detail for a suspect entry (integrity failure).
fn render_suspect_detail(w: &mut impl Write, suspect: &SuspectEntry) {
    let _ = writeln!(w, "  {} {}", suspect.program.bold(), "SUSPECT".red().bold());
    let _ = writeln!(
        w,
        "    {} {}",
        "stored hash:".dimmed(),
        suspect.stored_hash.dimmed()
    );
    for rule in &suspect.stored_rules {
        let _ = writeln!(w, "    {}", rule.dimmed());
    }
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

/// Interactive approval for trust operations. Returns list of approved programs.
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

        render_entry_detail(
            &mut std::io::stderr(),
            program,
            status_str,
            meta,
            if *status == TrustStatus::Changed {
                store.previous_rules(program)
            } else {
                None
            },
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

/// Batch (non-interactive) approval — approve all without prompting.
pub fn batch_approve(store: &mut TrustStore, hashes: &TrustHashes) -> Vec<String> {
    let mut approved = Vec::new();
    for (program, meta) in &hashes.programs {
        store.approve(
            program.clone(),
            meta.hash.clone(),
            meta.canonical_rules.clone(),
        );
        approved.push(program.clone());
    }
    approved
}

/// Collect pending (NEW/CHANGED) entries from hashes against the store.
pub fn pending_entries<'a>(
    store: &TrustStore,
    hashes: &'a TrustHashes,
) -> Vec<(&'a str, &'a ProgramMeta, TrustStatus)> {
    hashes
        .programs
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

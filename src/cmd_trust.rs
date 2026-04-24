// Trust subcommand — view and approve trust for loaded config programs.

use std::collections::BTreeMap;
use std::io::Write;

use colored::Colorize;
use may_i_config as config;
use may_i_engine::trust::{ProgramMeta, TrustHashes, compute_trust_hashes};

use crate::interactive;
use crate::output;
use crate::trust_store::{TrustStatus, TrustStore, default_trust_store_path};

/// Run the trust subcommand.
///
/// - No program and no `--all`: list trust status for all programs.
/// - `--all`: approve all pending programs.
/// - With a program name: approve that specific program.
pub fn cmd_trust(
    program: Option<&str>,
    all: bool,
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let loaded = config::load_and_resolve(config_path)?;
    let hashes = compute_trust_hashes(&loaded.config);

    if hashes.programs.is_empty() {
        if json_mode {
            println!("[]");
        } else {
            eprintln!("No loaded config content requires trust approval.");
        }
        return Ok(());
    }

    let store_path = default_trust_store_path()
        .ok_or_else(|| miette::miette!("cannot determine trust store path"))?;
    let load_result = TrustStore::load(&store_path)
        .map_err(|e| miette::miette!("failed to read trust store: {e}"))?;
    let mut store = load_result.store;

    let is_tty = interactive::is_interactive(json_mode);

    // Handle integrity repair before any operation.
    if !load_result.suspects.is_empty() {
        let modified = interactive::repair_integrity(&mut store, &load_result.suspects, is_tty)?;
        if modified {
            store
                .save(&store_path)
                .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;
        }
    }

    if all {
        approve_all(&mut store, &hashes, &store_path, json_mode, is_tty)
    } else if let Some(prog) = program {
        approve_one(&mut store, &hashes, prog, &store_path, json_mode, is_tty)
    } else {
        list_status(&mut store, &hashes, &store_path, json_mode, is_tty)
    }
}

fn approve_all(
    store: &mut TrustStore,
    hashes: &TrustHashes,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let approved = if is_tty {
        let pending = interactive::pending_entries(store, hashes);
        if pending.is_empty() {
            eprintln!("All programs already trusted.");
            return Ok(());
        }
        interactive::interactive_approve(store, &pending)?
    } else {
        interactive::batch_approve(store, hashes)
    };

    store
        .save(store_path)
        .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

    if json_mode {
        let json = serde_json::json!({ "approved": approved });
        println!(
            "{}",
            serde_json::to_string(&json).expect("serialization is infallible")
        );
    } else if !is_tty {
        for prog in &approved {
            eprintln!("Approved: {prog}");
        }
    }
    Ok(())
}

fn approve_one(
    store: &mut TrustStore,
    hashes: &TrustHashes,
    program: &str,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let meta = hashes
        .programs
        .get(program)
        .ok_or_else(|| miette::miette!("no loaded rules found for program '{program}'"))?;

    let status = store.check(program, &meta.hash);
    if status == TrustStatus::Trusted {
        if json_mode {
            let json = serde_json::json!({ "program": program, "status": "trusted" });
            println!(
                "{}",
                serde_json::to_string(&json).expect("serialization is infallible")
            );
        } else {
            eprintln!("{program}: already trusted");
        }
        return Ok(());
    }

    if is_tty {
        let entries = vec![(program, meta, status)];
        let approved = interactive::interactive_approve(store, &entries)?;
        if approved.is_empty() {
            return Ok(());
        }
    } else {
        store.approve(
            program.to_string(),
            meta.hash.clone(),
            meta.canonical_rules.clone(),
        );
    }

    store
        .save(store_path)
        .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

    if json_mode {
        let json = serde_json::json!({ "approved": [program] });
        println!(
            "{}",
            serde_json::to_string(&json).expect("serialization is infallible")
        );
    } else if !is_tty {
        eprintln!("Approved: {program}");
    }
    Ok(())
}

fn list_status(
    store: &mut TrustStore,
    hashes: &TrustHashes,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    if json_mode {
        list_status_json(store, hashes);
    } else {
        list_status_human(store, hashes);

        // Offer to approve pending entries interactively.
        if is_tty {
            let pending = interactive::pending_entries(store, hashes);
            if !pending.is_empty() {
                eprintln!();
                let walk = dialoguer::Confirm::new()
                    .with_prompt("Review and approve pending entries?")
                    .default(true)
                    .interact()
                    .map_err(|e| miette::miette!("prompt failed: {e}"))?;

                if walk {
                    let approved = interactive::interactive_approve(store, &pending)?;
                    if !approved.is_empty() {
                        store
                            .save(store_path)
                            .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn list_status_json(store: &TrustStore, hashes: &TrustHashes) {
    let entries: Vec<serde_json::Value> = hashes
        .programs
        .iter()
        .map(|(program, meta)| {
            let status = store.check(program, &meta.hash);
            let status_str = match status {
                TrustStatus::Trusted => "trusted",
                TrustStatus::Changed => "changed",
                TrustStatus::New => "new",
            };
            let files: Vec<String> = meta
                .source_files
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            let mut entry = serde_json::json!({
                "program": program,
                "status": status_str,
                "files": files,
                "rules": meta.canonical_rules,
            });
            if status == TrustStatus::Changed
                && let Some(prev) = store.previous_rules(program)
            {
                entry["previousRules"] = serde_json::json!(prev);
            }
            entry
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&entries).expect("serialization is infallible")
    );
}

fn list_status_human(store: &TrustStore, hashes: &TrustHashes) {
    let mut w = std::io::stderr();

    // Partition into trusted and pending entries.
    let mut trusted: Vec<(&str, &ProgramMeta)> = Vec::new();
    let mut pending: Vec<(&str, &ProgramMeta, TrustStatus)> = Vec::new();

    for (program, meta) in &hashes.programs {
        let status = store.check(program, &meta.hash);
        match status {
            TrustStatus::Trusted => trusted.push((program.as_str(), meta)),
            _ => pending.push((program.as_str(), meta, status)),
        }
    }

    // Show pending entries with detail.
    for (program, meta, status) in &pending {
        let status_str = match status {
            TrustStatus::New => "NEW",
            TrustStatus::Changed => "CHANGED",
            TrustStatus::Trusted => unreachable!(),
        };
        let badge = match status {
            TrustStatus::New => status_str.yellow().bold().to_string(),
            TrustStatus::Changed => status_str.red().bold().to_string(),
            TrustStatus::Trusted => unreachable!(),
        };

        let _ = writeln!(w, "  {} {}", program.bold(), badge);

        for file in &meta.source_files {
            let _ = writeln!(w, "    {} {}", "file:".dimmed(), output::shorten_home(file));
        }

        if *status == TrustStatus::Changed {
            if let Some(prev) = store.previous_rules(program) {
                render_diff(&mut w, prev, &meta.canonical_rules);
            }
        } else {
            for rule in &meta.canonical_rules {
                let _ = writeln!(w, "    {}", rule.dimmed());
            }
        }
        let _ = writeln!(w);
    }

    // Show trusted entries grouped by file.
    if !trusted.is_empty() {
        if !pending.is_empty() {
            let _ = writeln!(w, "  {}", "Trusted:".dimmed());
        }
        let grouped = group_by_file(&trusted);
        let term = output::Terminal::detect();
        let rows: Vec<output::ColRow> = grouped
            .iter()
            .map(|(file, programs)| {
                let names = programs.join(", ");
                let right = output::shorten_home(file).dimmed().to_string();
                output::ColRow::new(names.clone(), names.len(), right)
            })
            .collect();

        let layout = output::Layout::Indent(2, Box::new(output::Layout::Columns(rows)));
        output::write_layout(&mut w, &layout, &term);

        if pending.is_empty() {
            let _ = writeln!(w);
            let _ = writeln!(w, "  {}", "All trusted.".green());
        }
    }
}

/// Render line-level diff between old and new rule forms.
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

/// Group programs by their source file. Returns file → [program names] in file order.
fn group_by_file<'a>(
    trusted: &[(&'a str, &'a ProgramMeta)],
) -> Vec<(&'a std::path::Path, Vec<&'a str>)> {
    let mut map: BTreeMap<&std::path::Path, Vec<&str>> = BTreeMap::new();
    for (program, meta) in trusted {
        if meta.source_files.is_empty() {
            // Shouldn't happen for loaded rules, but handle gracefully.
            map.entry(std::path::Path::new("<unknown>"))
                .or_default()
                .push(program);
        } else {
            for file in &meta.source_files {
                map.entry(file.as_path()).or_default().push(program);
            }
        }
    }
    map.into_iter().collect()
}

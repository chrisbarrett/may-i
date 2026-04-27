// Trust subcommand — view and approve trust for loaded config programs.

use std::collections::BTreeMap;
use std::io::Write;

use colored::Colorize;
use may_i_config as config;
use may_i_engine::trust::{ProgramMeta, RuleMeta, TrustHashes, compute_trust_hashes};

use crate::interactive;
use crate::output;
use crate::trust_store::{TrustCheck, TrustStatus, TrustStore, default_trust_store_path};

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

    if hashes.is_empty() {
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

    let programs = hashes.programs();

    if all {
        approve_all(
            &mut store,
            &hashes,
            &programs,
            &store_path,
            json_mode,
            is_tty,
        )
    } else if let Some(prog) = program {
        approve_one(&mut store, &programs, prog, &store_path, json_mode, is_tty)
    } else {
        list_status(
            &mut store,
            &hashes,
            &programs,
            &store_path,
            json_mode,
            is_tty,
        )
    }
}

fn approve_all(
    store: &mut TrustStore,
    hashes: &TrustHashes,
    programs: &BTreeMap<String, ProgramMeta>,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let approved = if is_tty {
        let pending = interactive::pending_entries(store, programs);
        if pending.is_empty() {
            eprintln!("All programs already trusted.");
            return Ok(());
        }
        interactive::interactive_approve(store, &pending)?
    } else {
        interactive::batch_approve(store, hashes, programs)
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
    programs: &BTreeMap<String, ProgramMeta>,
    program: &str,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let meta = programs
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
    programs: &BTreeMap<String, ProgramMeta>,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    if json_mode {
        list_status_json(store, hashes);
        return Ok(());
    }

    let has_pending = hashes
        .rules
        .iter()
        .any(|r| store.check_rule(&r.hash) == TrustCheck::Pending);

    if is_tty && has_pending {
        // Skip the full dump — go straight into per-rule review.
        let (_approved, _summary) = interactive::interactive_review(store, hashes)?;
        store
            .save(store_path)
            .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

        // Show grouped-by-file trusted summary only — no rule forms.
        print_trusted_summary(store, hashes, programs);
    } else {
        list_status_human(store, hashes, programs);
    }
    Ok(())
}

/// Print only the grouped-by-file trusted summary, without re-showing any rule forms.
fn print_trusted_summary(
    store: &TrustStore,
    hashes: &TrustHashes,
    programs: &BTreeMap<String, ProgramMeta>,
) {
    let mut w = std::io::stderr();

    let mut by_program: BTreeMap<&str, Vec<&RuleMeta>> = BTreeMap::new();
    for rule_meta in &hashes.rules {
        by_program
            .entry(&rule_meta.program)
            .or_default()
            .push(rule_meta);
    }

    let trusted: Vec<(&str, &ProgramMeta)> = by_program
        .iter()
        .filter(|(_, rules)| {
            rules
                .iter()
                .all(|r| store.check_rule(&r.hash) == TrustCheck::Approved)
        })
        .filter_map(|(program, _)| {
            programs
                .get_key_value(*program)
                .map(|(k, v)| (k.as_str(), v))
        })
        .collect();

    if trusted.is_empty() {
        return;
    }

    let grouped = group_by_file(&trusted);
    let term = output::Terminal::detect();
    let rows: Vec<output::ColRow> = grouped
        .iter()
        .map(|(file, progs)| {
            let names = progs.join(", ");
            let right = output::shorten_home(file).dimmed().to_string();
            output::ColRow::new(names.clone(), names.len(), right)
        })
        .collect();

    let layout = output::Layout::Indent(2, Box::new(output::Layout::Columns(rows)));
    output::write_layout(&mut w, &layout, &term);
}

/// Per-rule JSON output.
fn list_status_json(store: &TrustStore, hashes: &TrustHashes) {
    let entries: Vec<serde_json::Value> = hashes
        .rules
        .iter()
        .map(|rule_meta| {
            let status = store.check_rule(&rule_meta.hash);
            let status_str = match status {
                TrustCheck::Approved => "approved",
                TrustCheck::Blocked => "blocked",
                TrustCheck::Pending => "pending",
            };
            let file = rule_meta
                .source_file
                .as_ref()
                .map(|p| p.display().to_string());
            let mut entry = serde_json::json!({
                "program": rule_meta.program,
                "hash": rule_meta.hash,
                "form": rule_meta.canonical_form,
                "status": status_str,
            });
            if let Some(f) = file {
                entry["file"] = serde_json::json!(f);
            }
            entry
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&entries).expect("serialization is infallible")
    );
}

/// Per-rule human-readable listing grouped by program.
fn list_status_human(
    store: &TrustStore,
    hashes: &TrustHashes,
    programs: &BTreeMap<String, ProgramMeta>,
) {
    let mut w = std::io::stderr();

    // Group rules by program.
    let mut by_program: BTreeMap<&str, Vec<&RuleMeta>> = BTreeMap::new();
    for rule_meta in &hashes.rules {
        by_program
            .entry(&rule_meta.program)
            .or_default()
            .push(rule_meta);
    }

    let mut has_pending = false;
    let mut all_approved_programs: Vec<(&str, &ProgramMeta)> = Vec::new();

    for (program, rule_metas) in &by_program {
        let statuses: Vec<TrustCheck> = rule_metas
            .iter()
            .map(|r| store.check_rule(&r.hash))
            .collect();

        let all_approved = statuses.iter().all(|s| *s == TrustCheck::Approved);

        if all_approved {
            if let Some(meta) = programs.get(*program) {
                all_approved_programs.push((program, meta));
            }
            continue;
        }

        has_pending = true;

        let _ = writeln!(w, "  {}", program.bold());

        for (rule_meta, status) in rule_metas.iter().zip(statuses.iter()) {
            let (_badge_text, badge_colored) = match status {
                TrustCheck::Approved => ("approved", "approved".green().to_string()),
                TrustCheck::Blocked => ("blocked", "blocked".red().to_string()),
                TrustCheck::Pending => ("pending", "pending".yellow().to_string()),
            };
            let pretty = interactive::pretty_form(&rule_meta.canonical_form, 72, true);
            let first_line = pretty.lines().next().unwrap_or(&rule_meta.canonical_form);
            let _ = writeln!(w, "    {} {}", first_line, badge_colored);
            for line in pretty.lines().skip(1) {
                let _ = writeln!(w, "    {}", line);
            }
            if let Some(file) = &rule_meta.source_file {
                let _ = writeln!(
                    w,
                    "      {} {}",
                    "file:".dimmed(),
                    output::shorten_home(file)
                );
            }
        }
        let _ = writeln!(w);
    }

    // Show fully-approved programs grouped by file.
    if !all_approved_programs.is_empty() {
        if has_pending {
            let _ = writeln!(w, "  {}", "Trusted:".dimmed());
        }
        let grouped = group_by_file(&all_approved_programs);
        let term = output::Terminal::detect();
        let rows: Vec<output::ColRow> = grouped
            .iter()
            .map(|(file, progs)| {
                let names = progs.join(", ");
                let right = output::shorten_home(file).dimmed().to_string();
                output::ColRow::new(names.clone(), names.len(), right)
            })
            .collect();

        let layout = output::Layout::Indent(2, Box::new(output::Layout::Columns(rows)));
        output::write_layout(&mut w, &layout, &term);

        if !has_pending {
            let _ = writeln!(w);
            let _ = writeln!(w, "  {}", "All trusted.".green());
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

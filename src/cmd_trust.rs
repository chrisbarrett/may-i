// Trust subcommand — view and approve trust for loaded config programs.

use std::collections::BTreeMap;
use std::io::Write;

use colored::Colorize;
use may_i_config as config;

use crate::interactive;
use crate::output;
use crate::trust::store::{TrustStore, default_trust_store_path};
use crate::trust::view::{TrustCatalog, TrustState, TrustView, build_catalog};

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

    let store_path = default_trust_store_path()
        .ok_or_else(|| miette::miette!("cannot determine trust store path"))?;
    let load_result = TrustStore::load(&store_path)
        .map_err(|e| miette::miette!("failed to read trust store: {e}"))?;
    let mut store = load_result.store;

    let is_tty = interactive::is_interactive(json_mode);

    // Handle integrity repair before any operation — repair mutates the store
    // before the catalog join.
    if !load_result.suspects.is_empty() {
        let modified = interactive::repair_integrity(&mut store, &load_result.suspects, is_tty)?;
        if modified {
            store
                .save(&store_path)
                .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;
        }
    }

    let mut catalog = build_catalog(&loaded.config, store);

    if catalog.is_empty() {
        if json_mode {
            println!("[]");
        } else {
            eprintln!("No loaded config content requires trust approval.");
        }
        return Ok(());
    }

    if all {
        approve_all(&mut catalog, &store_path, json_mode, is_tty)
    } else if let Some(prog) = program {
        approve_one(&mut catalog, prog, &store_path, json_mode, is_tty)
    } else {
        list_status(&mut catalog, &store_path, json_mode, is_tty)
    }
}

fn approve_all(
    catalog: &mut TrustCatalog,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let pending = interactive::pending_programs(catalog);
    if pending.is_empty() {
        if json_mode {
            let empty: Vec<String> = Vec::new();
            let json = serde_json::json!({ "approved": empty });
            println!(
                "{}",
                serde_json::to_string(&json).expect("serialization is infallible")
            );
        } else {
            eprintln!("All programs already trusted.");
        }
        return Ok(());
    }

    let approved = if is_tty {
        interactive::interactive_approve_programs(catalog, &pending)?
    } else {
        interactive::batch_approve(catalog)
    };

    catalog
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
    catalog: &mut TrustCatalog,
    program: &str,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    let groups = catalog.group_by_program();
    let views = groups
        .get(program)
        .ok_or_else(|| miette::miette!("no loaded rules found for program '{program}'"))?;

    if views.iter().all(|v| v.state() == TrustState::Approved) {
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

    let hashes: Vec<String> = views.iter().map(|v| v.hash().to_string()).collect();
    drop(groups);

    if is_tty {
        let approved = interactive::interactive_approve_programs(catalog, &[program.to_string()])?;
        if approved.is_empty() {
            return Ok(());
        }
    } else {
        for hash in &hashes {
            catalog.set_state(hash, TrustState::Approved);
        }
    }

    catalog
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
    catalog: &mut TrustCatalog,
    store_path: &std::path::Path,
    json_mode: bool,
    is_tty: bool,
) -> miette::Result<()> {
    if json_mode {
        list_status_json(catalog);
        return Ok(());
    }

    let has_pending = catalog.iter().any(|v| v.state() == TrustState::Pending);

    if is_tty && has_pending {
        let (_approved, _summary) = interactive::interactive_review(catalog)?;
        catalog
            .save(store_path)
            .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

        print_trusted_summary(catalog);
    } else {
        list_status_human(catalog);
    }
    Ok(())
}

/// Print only the grouped-by-file trusted summary, without re-showing any rule forms.
fn print_trusted_summary(catalog: &TrustCatalog) {
    let mut w = std::io::stderr();

    let groups = catalog.group_by_program();
    let trusted: Vec<(&str, &Vec<&TrustView>)> = groups
        .iter()
        .filter(|(_, views)| views.iter().all(|v| v.state() == TrustState::Approved))
        .map(|(p, vs)| (*p, vs))
        .collect();

    if trusted.is_empty() {
        return;
    }

    let grouped = group_by_file(&trusted);
    let term = output::Terminal::detect();
    output::render_trusted_groups(&mut w, &term, &grouped);
}

/// Per-rule JSON output.
fn list_status_json(catalog: &TrustCatalog) {
    let entries: Vec<serde_json::Value> = catalog
        .iter()
        .map(|view| {
            let status_str = match view.state() {
                TrustState::Approved => "approved",
                TrustState::Blocked => "blocked",
                TrustState::Pending => "pending",
            };
            let mut entry = serde_json::json!({
                "program": view.program(),
                "hash": view.hash(),
                "form": view.canonical_form(),
                "status": status_str,
            });
            if let Some(f) = view.source_file() {
                entry["file"] = serde_json::json!(f.display().to_string());
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
fn list_status_human(catalog: &TrustCatalog) {
    let mut w = std::io::stderr();

    let groups = catalog.group_by_program();

    let mut has_pending = false;
    let mut all_approved_programs: Vec<(&str, &Vec<&TrustView>)> = Vec::new();

    for (program, views) in &groups {
        let all_approved = views.iter().all(|v| v.state() == TrustState::Approved);

        if all_approved {
            all_approved_programs.push((program, views));
            continue;
        }

        has_pending = true;

        let _ = writeln!(w, "  {}", program.bold());

        for view in views {
            let badge_colored = match view.state() {
                TrustState::Approved => "approved".green().to_string(),
                TrustState::Blocked => "blocked".red().to_string(),
                TrustState::Pending => "pending".yellow().to_string(),
            };
            let pretty = interactive::pretty_form(view.canonical_form(), 72, true);
            let first_line = pretty.lines().next().unwrap_or(view.canonical_form());
            let _ = writeln!(w, "    {} {}", first_line, badge_colored);
            for line in pretty.lines().skip(1) {
                let _ = writeln!(w, "    {}", line);
            }
            if let Some(file) = view.source_file() {
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
        output::render_trusted_groups(&mut w, &term, &grouped);

        if !has_pending {
            let _ = writeln!(w);
            let _ = writeln!(w, "  {}", "All trusted.".green());
        }
    }
}

/// Group programs by their source file. Returns file → [program names] in file order.
fn group_by_file<'a>(
    trusted: &[(&'a str, &'a Vec<&'a TrustView>)],
) -> Vec<(&'a std::path::Path, Vec<&'a str>)> {
    let mut map: BTreeMap<&std::path::Path, Vec<&str>> = BTreeMap::new();
    for (program, views) in trusted {
        let files: std::collections::BTreeSet<&std::path::Path> =
            views.iter().filter_map(|v| v.source_file()).collect();
        if files.is_empty() {
            map.entry(std::path::Path::new("<unknown>"))
                .or_default()
                .push(program);
        } else {
            for file in files {
                map.entry(file).or_default().push(program);
            }
        }
    }
    map.into_iter().collect()
}

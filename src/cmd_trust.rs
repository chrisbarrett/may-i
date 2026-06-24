// Trust subcommand — view and approve trust for loaded config programs.

use std::collections::BTreeMap;
use std::io::Write;

use may_i_config as config;
use may_i_output::{Style, Styled};

use crate::interactive;
use crate::output::{self, TrustListing};
use crate::sink;
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
    crate::sink::flush_config_advisories();

    let store_path = default_trust_store_path()
        .ok_or_else(|| miette::miette!("cannot determine trust store path"))?;
    let load_result = TrustStore::load(&store_path).map_err(|e| {
        miette::miette!(
            "failed to read trust store: {}",
            may_i_core::SafeText::new(e.to_string())
        )
    })?;
    let mut store = load_result.store;

    let is_tty = interactive::is_interactive(json_mode);

    // Handle integrity repair before any operation — repair mutates the store
    // before the catalog join.
    if !load_result.suspects.is_empty() {
        let modified = interactive::repair_integrity(&mut store, &load_result.suspects, is_tty)?;
        if modified {
            store.save(&store_path).map_err(|e| {
                miette::miette!(
                    "failed to save trust store: {}",
                    may_i_core::SafeText::new(e.to_string())
                )
            })?;
        }
    }

    let mut catalog = build_catalog(&loaded.config, store);

    if catalog.is_empty() {
        if json_mode {
            sink::with_stdout(|w| {
                let _ = writeln!(w, "[]");
            });
        } else {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "No loaded config content requires trust approval.");
            });
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
            sink::with_stdout(|w| {
                let _ = writeln!(
                    w,
                    "{}",
                    serde_json::to_string(&json).expect("serialization is infallible")
                );
            });
        } else {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "All programs already trusted.");
            });
        }
        return Ok(());
    }

    let approved = if is_tty {
        interactive::interactive_approve_programs(catalog, &pending)?
    } else {
        interactive::batch_approve(catalog)
    };

    catalog.save(store_path).map_err(|e| {
        miette::miette!(
            "failed to save trust store: {}",
            may_i_core::SafeText::new(e.to_string())
        )
    })?;

    if json_mode {
        let json = serde_json::json!({ "approved": approved });
        sink::with_stdout(|w| {
            let _ = writeln!(
                w,
                "{}",
                serde_json::to_string(&json).expect("serialization is infallible")
            );
        });
    } else if !is_tty {
        sink::with_stderr(|w| {
            for prog in &approved {
                let _ = writeln!(w, "Approved: {prog}");
            }
        });
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
    let views = groups.get(program).ok_or_else(|| {
        miette::miette!(
            "no loaded rules found for program '{}'",
            may_i_core::SafeText::new(program)
        )
    })?;

    if views.iter().all(|v| v.state() == TrustState::Approved) {
        if json_mode {
            let json = serde_json::json!({ "program": program, "status": "trusted" });
            sink::with_stdout(|w| {
                let _ = writeln!(
                    w,
                    "{}",
                    serde_json::to_string(&json).expect("serialization is infallible")
                );
            });
        } else {
            sink::with_stderr(|w| {
                let _ = writeln!(w, "{program}: already trusted");
            });
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

    catalog.save(store_path).map_err(|e| {
        miette::miette!(
            "failed to save trust store: {}",
            may_i_core::SafeText::new(e.to_string())
        )
    })?;

    if json_mode {
        let json = serde_json::json!({ "approved": [program] });
        sink::with_stdout(|w| {
            let _ = writeln!(
                w,
                "{}",
                serde_json::to_string(&json).expect("serialization is infallible")
            );
        });
    } else if !is_tty {
        sink::with_stderr(|w| {
            let _ = writeln!(w, "Approved: {program}");
        });
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
        catalog.save(store_path).map_err(|e| {
            miette::miette!(
                "failed to save trust store: {}",
                may_i_core::SafeText::new(e.to_string())
            )
        })?;

        print_trusted_summary(catalog);
    } else {
        list_status_human(catalog);
    }
    Ok(())
}

/// Print only the grouped-by-file trusted summary, without re-showing any rule forms.
fn print_trusted_summary(catalog: &TrustCatalog) {
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
    let term = output::Terminal::detect().with_color(crate::sink::stderr_color());
    sink::with_stderr(|w| {
        TrustListing {
            heading: None,
            groups: &grouped,
        }
        .render(w, &term);
    });
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
    sink::with_stdout(|w| {
        let _ = writeln!(
            w,
            "{}",
            serde_json::to_string(&entries).expect("serialization is infallible")
        );
    });
}

/// Per-rule human-readable listing grouped by program.
fn list_status_human(catalog: &TrustCatalog) {
    let color = crate::sink::stderr_color();
    let term = output::Terminal::detect().with_color(color);

    let groups = catalog.group_by_program();

    sink::with_stderr(|w| {
        let mut has_pending = false;
        let mut all_approved_programs: Vec<(&str, &Vec<&TrustView>)> = Vec::new();

        for (program, views) in &groups {
            let all_approved = views.iter().all(|v| v.state() == TrustState::Approved);

            if all_approved {
                all_approved_programs.push((program, views));
                continue;
            }

            has_pending = true;

            may_i_output::write_line(w, &Styled::plain("  ").with(*program, Style::Strong), &term);

            for view in views {
                let (badge_text, badge_style) = match view.state() {
                    TrustState::Approved => ("approved", Style::AllowSoft),
                    TrustState::Blocked => ("blocked", Style::DenySoft),
                    TrustState::Pending => ("pending", Style::AskSoft),
                };
                let mut badge_buf = Vec::new();
                may_i_output::write_line(
                    &mut badge_buf,
                    &Styled::span(badge_text, badge_style),
                    &term,
                );
                let badge = String::from_utf8(badge_buf).unwrap_or_default();
                let badge = badge.trim_end();
                let pretty = interactive::pretty_form(view.canonical_form(), 72, color);
                let first_line = pretty.lines().next().unwrap_or(view.canonical_form());
                let _ = writeln!(w, "    {first_line} {badge}");
                for line in pretty.lines().skip(1) {
                    let _ = writeln!(w, "    {}", line);
                }
                if let Some(file) = view.source_file() {
                    let mut file_buf = Vec::new();
                    may_i_output::write_line(
                        &mut file_buf,
                        &Styled::span("file:", Style::Dimmed),
                        &term,
                    );
                    let file_label = String::from_utf8(file_buf).unwrap_or_default();
                    let file_label = file_label.trim_end();
                    let _ = writeln!(w, "      {} {}", file_label, output::shorten_home(file));
                }
            }
            let _ = writeln!(w);
        }

        // Show fully-approved programs grouped by file.
        if !all_approved_programs.is_empty() {
            let grouped = group_by_file(&all_approved_programs);
            TrustListing {
                heading: has_pending.then_some("Trusted:"),
                groups: &grouped,
            }
            .render(w, &term);

            if !has_pending {
                let mut all_buf = Vec::new();
                may_i_output::write_line(
                    &mut all_buf,
                    &Styled::span("All trusted.", Style::AllowSoft),
                    &term,
                );
                let all_trusted = String::from_utf8(all_buf).unwrap_or_default();
                let all_trusted = all_trusted.trim_end();
                let _ = writeln!(w);
                let _ = writeln!(w, "  {}", all_trusted);
            }
        }
    });
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

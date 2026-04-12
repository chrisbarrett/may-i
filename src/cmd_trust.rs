// Trust subcommand — view and approve trust for loaded config programs.

use may_i_config as config;
use may_i_engine::trust::compute_trust_hashes;

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
    let mut store = TrustStore::load(&store_path)
        .map_err(|e| miette::miette!("failed to read trust store: {e}"))?;

    if all {
        approve_all(&mut store, &hashes, &store_path, json_mode)
    } else if let Some(prog) = program {
        approve_one(&mut store, &hashes, prog, &store_path, json_mode)
    } else {
        list_status(&store, &hashes, json_mode)
    }
}

fn approve_all(
    store: &mut TrustStore,
    hashes: &may_i_engine::trust::TrustHashes,
    store_path: &std::path::Path,
    json_mode: bool,
) -> miette::Result<()> {
    let mut approved = Vec::new();
    for (program, hash) in &hashes.programs {
        store.approve(program.clone(), hash.clone());
        approved.push(program.as_str());
    }
    store
        .save(store_path)
        .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

    if json_mode {
        let json = serde_json::json!({ "approved": approved });
        println!(
            "{}",
            serde_json::to_string(&json).expect("serialization is infallible")
        );
    } else {
        for prog in &approved {
            eprintln!("Approved: {prog}");
        }
    }
    Ok(())
}

fn approve_one(
    store: &mut TrustStore,
    hashes: &may_i_engine::trust::TrustHashes,
    program: &str,
    store_path: &std::path::Path,
    json_mode: bool,
) -> miette::Result<()> {
    let hash = hashes
        .programs
        .get(program)
        .ok_or_else(|| miette::miette!("no loaded rules found for program '{program}'"))?;

    store.approve(program.to_string(), hash.clone());
    store
        .save(store_path)
        .map_err(|e| miette::miette!("failed to save trust store: {e}"))?;

    if json_mode {
        let json = serde_json::json!({ "approved": [program] });
        println!(
            "{}",
            serde_json::to_string(&json).expect("serialization is infallible")
        );
    } else {
        eprintln!("Approved: {program}");
    }
    Ok(())
}

fn list_status(
    store: &TrustStore,
    hashes: &may_i_engine::trust::TrustHashes,
    json_mode: bool,
) -> miette::Result<()> {
    if json_mode {
        let entries: Vec<serde_json::Value> = hashes
            .programs
            .iter()
            .map(|(program, hash)| {
                let status = store.check(program, hash);
                serde_json::json!({
                    "program": program,
                    "status": match status {
                        TrustStatus::Trusted => "trusted",
                        TrustStatus::Changed => "changed",
                        TrustStatus::New => "new",
                    },
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&entries).expect("serialization is infallible")
        );
    } else {
        for (program, hash) in &hashes.programs {
            let status = store.check(program, hash);
            let label = match status {
                TrustStatus::Trusted => "trusted",
                TrustStatus::Changed => "CHANGED",
                TrustStatus::New => "NEW",
            };
            eprintln!("  {program}: {label}");
        }
    }
    Ok(())
}

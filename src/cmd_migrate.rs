// Migration command for converting v1 configs to v2 syntax.

use std::path::Path;

use may_i_config::v2::migrate::{migrate_forms, validate_migration};
use may_i_sexpr::parse_cst;

/// Run the migration command.
pub fn cmd_migrate(
    config_path: Option<&Path>,
    output: Option<&str>,
    dry_run: bool,
    diff: bool,
    no_validate: bool,
) -> miette::Result<()> {
    // Resolve config file path using the same mechanism as other commands
    let config_file = may_i_config::resolve_path(config_path)?;

    // Read input from the resolved config file
    let source = std::fs::read_to_string(&config_file)
        .map_err(|e| miette::miette!("Failed to read config file: {e}"))?;

    // Parse the source
    let (forms, errors): (
        Vec<Box<may_i_sexpr::cst::CstNode>>,
        Vec<may_i_sexpr::RawError>,
    ) = parse_cst(&source);

    if !errors.is_empty() {
        eprintln!("Parse errors:");
        for err in &errors {
            eprintln!("  {err}");
        }
    }

    // Task 6.8: Check for unhandled v1 constructs
    let unhandled = may_i_config::v2::migrate::check_unhandled_cases(&source);
    if !unhandled.is_empty() {
        eprintln!(
            "\nWarning: Found {} unhandled v1 construct(s) that may need manual attention:",
            unhandled.len()
        );
        for case in &unhandled {
            eprintln!("\n  {}:", case.description);
            eprintln!("    Source: {}", case.source.trim());
            eprintln!("    Suggestion: {}", case.suggestion);
        }
        eprintln!();
    }

    // Apply migration
    let migrated = migrate_forms(forms);

    // Generate output
    let output_text = migrated
        .iter()
        .map(|f| f.serialize())
        .collect::<Vec<_>>()
        .join("");

    // Task 6.7: Validate migration output parses with v2 parser
    if !no_validate {
        if let Err(validation_errors) = validate_migration(&output_text) {
            eprintln!("\nMigration validation failed:");
            for err in &validation_errors {
                eprintln!("  Error: {}", err);
            }
            eprintln!("\nThe migrated config could not be parsed by the v2 parser.");
            eprintln!("This may indicate an unhandled migration case.");
            eprintln!("Use --no-validate to skip validation.");
            return Err(miette::miette!("Migration validation failed"));
        } else {
            println!("✓ Migration output validated successfully");
        }
    }

    // Show diff if requested
    if diff {
        show_diff(&source, &output_text);
    }

    // Determine output path: use provided output, or default to the input config file for in-place migration
    let output_path = output.map(Path::new);

    // Write output or print
    if dry_run {
        println!("\nDry run - would produce:");
        println!("{}", output_text);
    } else if let Some(path) = output_path {
        std::fs::write(path, output_text)
            .map_err(|e| miette::miette!("Failed to write output file: {e}"))?;
        println!("Migrated config written to {}", path.display());
    } else {
        // In-place migration: write back to the source config file
        std::fs::write(&config_file, output_text)
            .map_err(|e| miette::miette!("Failed to write config file: {e}"))?;
        println!(
            "Migrated config written to {} (in-place)",
            config_file.display()
        );
    }

    Ok(())
}

fn show_diff(original: &str, migrated: &str) {
    // Simple line-by-line diff
    let original_lines: Vec<_> = original.lines().collect();
    let migrated_lines: Vec<_> = migrated.lines().collect();

    println!("\nDiff:");
    println!("-----");

    let max_lines = original_lines.len().max(migrated_lines.len());

    for i in 0..max_lines {
        let orig = original_lines.get(i);
        let mig = migrated_lines.get(i);

        match (orig, mig) {
            (Some(o), Some(m)) if o != m => {
                println!("- {}", o);
                println!("+ {}", m);
            }
            (Some(o), None) => {
                println!("- {}", o);
            }
            (None, Some(m)) => {
                println!("+ {}", m);
            }
            _ => {}
        }
    }

    println!("-----\n");
}

// Migration command — convert v1 configs to canonical syntax.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use colored::Colorize;
use may_i_config::migrate::{migrate_forms, validate_migration};
use may_i_pp::detect_column_width;
use may_i_sexpr::parse_cst;
use similar::{ChangeTag, TextDiff};

fn generate_diff(original: &str, migrated: &str, config_path: &Path, use_color: bool) -> String {
    let diff = TextDiff::from_lines(original, migrated);
    let mut output = String::new();

    let display_path = may_i::output::shorten_home(config_path);
    output.push_str(&format!("{}:\n", display_path));

    let mut has_changes = false;

    for group in diff.grouped_ops(3) {
        for op in group {
            for change in diff.iter_changes(&op) {
                has_changes = true;
                let line = change.value().trim_end_matches('\n');
                let (prefix, line) = match change.tag() {
                    ChangeTag::Delete if use_color => {
                        ("-".red().to_string(), line.red().to_string())
                    }
                    ChangeTag::Delete => ("-".to_string(), line.to_string()),
                    ChangeTag::Insert if use_color => {
                        ("+".green().to_string(), line.green().to_string())
                    }
                    ChangeTag::Insert => ("+".to_string(), line.to_string()),
                    ChangeTag::Equal => (" ".to_string(), line.to_string()),
                };
                output.push_str(&format!("{}{}\n", prefix, line));
            }
        }
    }

    if has_changes { output } else { String::new() }
}

fn should_use_color() -> bool {
    std::env::var("NO_COLOR").is_err() && io::stdout().is_terminal()
}

fn prompt_confirm(message: &str) -> io::Result<String> {
    print!("{}", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn cmd_migrate(
    config_path: Option<&Path>,
    output: Option<&str>,
    yes: bool,
    dry_run: bool,
) -> miette::Result<()> {
    let config_file = may_i_config::resolve_path(config_path)?;

    // Show trust advisory if applicable (best-effort, don't fail migration on trust errors).
    if let Ok(loaded) = may_i_config::load_and_resolve(config_path) {
        let term = may_i::output::Terminal::detect();
        may_i::trust_advisory::write_integrity_advisories(&loaded.config, &term);
        if let Some(layout) = may_i::trust_advisory::build_warning_layout(&loaded.config) {
            may_i::output::write_layout(&mut std::io::stderr(), &layout, &term);
        }
    }

    // When `-o` is provided we operate on the root file only — the user
    // is asking for a single migrated artifact at a specific path.
    // Otherwise walk the `(load …)` graph and migrate every reachable
    // file in place (or just preview, with --dry-run).
    let output_path = output.map(Path::new);
    let files: Vec<PathBuf> = if output_path.is_some() {
        vec![config_file.clone()]
    } else {
        may_i_config::walk_load_graph(&config_file)?
    };

    let mut changed_files: Vec<(PathBuf, String, String)> = Vec::new();
    let mut skipped_readonly: Vec<PathBuf> = Vec::new();

    for file in &files {
        let source = std::fs::read_to_string(file)
            .map_err(|e| miette::miette!("Failed to read {}: {e}", file.display()))?;

        let (original_forms, parse_errors) = parse_cst(&source);
        if let Some(err) = parse_errors.first() {
            return Err(may_i_config::ConfigError::from_raw(
                err.clone(),
                &source,
                &file.display().to_string(),
            )
            .into());
        }

        let migrated_forms = migrate_forms(original_forms.clone());
        let column_width = detect_column_width(&source);
        let output_text = migrated_forms
            .iter()
            .map(|f| f.pretty_serialize(column_width))
            .collect::<Vec<_>>()
            .join("");

        if let Err(validation_errors) = validate_migration(&output_text)
            && let Some(raw_err) = validation_errors.first()
        {
            return Err(may_i_config::ConfigError::from_raw(
                raw_err.clone(),
                &output_text,
                "<migrated-output>",
            )
            .into());
        }

        if source != output_text {
            // Detect read-only files up front so the user gets a clear
            // signal rather than a write failure mid-walk.
            let metadata = std::fs::metadata(file)
                .map_err(|e| miette::miette!("Failed to stat {}: {e}", file.display()))?;
            if metadata.permissions().readonly() {
                skipped_readonly.push(file.clone());
                continue;
            }
            changed_files.push((file.clone(), source, output_text));
        }
    }

    for path in &skipped_readonly {
        eprintln!("warning: skipped, not writable: {}", path.display());
    }

    if changed_files.is_empty() {
        println!("No migration needed - all files up to date.");
        return Ok(());
    }

    let use_color = should_use_color();
    if dry_run {
        for (path, before, after) in &changed_files {
            let diff = generate_diff(before, after, path, use_color);
            if !diff.is_empty() {
                println!("{diff}");
            }
        }
        println!(
            "Dry run: {} file(s) would be migrated. Re-run without --dry-run to apply.",
            changed_files.len()
        );
        return Ok(());
    }

    if !yes {
        for (path, before, after) in &changed_files {
            let diff = generate_diff(before, after, path, use_color);
            if !diff.is_empty() {
                println!("{diff}");
            }
        }

        let is_tty = io::stdin().is_terminal() && io::stdout().is_terminal();
        if !is_tty {
            // Output is piped — just show the diff as a preview.
            return Ok(());
        }

        let prompt = format!("Apply migration to {} file(s)? [y/N] ", changed_files.len());
        let response = prompt_confirm(&prompt)
            .map_err(|e| miette::miette!("Failed to read prompt response: {e}"))?;

        if response.is_empty() || !response.to_lowercase().starts_with('y') {
            println!("Migration cancelled.");
            return Ok(());
        }
    }

    if let Some(path) = output_path {
        // Single-file mode — write to the explicit output path.
        let (_, _, output_text) = changed_files.into_iter().next().unwrap();
        std::fs::write(path, output_text)
            .map_err(|e| miette::miette!("Failed to write output file: {e}"))?;
        println!("Migrated config written to {}", path.display());
    } else {
        for (path, _, output_text) in &changed_files {
            std::fs::write(path, output_text)
                .map_err(|e| miette::miette!("Failed to write {}: {e}", path.display()))?;
        }
        println!("Migrated {} file(s) in-place.", changed_files.len());

        // Class A trust-hash rehash: re-canonicalise every approved rule
        // entry so existing approvals carry over to the new canonical form.
        let rehashed = rehash_trust_store_class_a()?;
        if rehashed > 0 {
            println!(
                "Rehashed {rehashed} trust entr{} to the new canonical form.",
                if rehashed == 1 { "y" } else { "ies" }
            );
        }

        // Class B warning: the wrapper-boundary fix may change behaviour
        // for rules over sudo/xargs/etc. Re-load and scan the resolved
        // ruleset so users know to re-run their `(check …)` cases.
        if let Ok(loaded) = may_i_config::load_and_resolve(config_path) {
            warn_about_wrapper_rules(&loaded.config);
        }
    }

    Ok(())
}

/// Re-canonicalise every rule entry in the trust store and rewrite the
/// store with new hashes. Approvals (Approved/Blocked status) carry
/// forward to the new key. Returns the number of entries whose hash
/// changed.
fn rehash_trust_store_class_a() -> miette::Result<usize> {
    use may_i::trust_store::{RuleEntry, TrustStore, default_trust_store_path};

    let Some(store_path) = default_trust_store_path() else {
        return Ok(0);
    };
    if !store_path.exists() {
        return Ok(0);
    }
    let load = TrustStore::load(&store_path)
        .map_err(|e| miette::miette!("Failed to load trust store: {e}"))?;
    let mut store = load.store;
    let mut rehashed = 0usize;
    let entries: Vec<(String, RuleEntry)> = store
        .iter_rules()
        .map(|(h, e)| (h.to_string(), e.clone()))
        .collect();
    for (old_hash, entry) in entries {
        let Some(new_form) = recanonicalise_rule_form(&entry.form) else {
            continue;
        };
        if new_form == entry.form {
            continue;
        }
        let new_hash = may_i_engine::trust::hash_rule(&new_form);
        if new_hash == old_hash {
            continue;
        }
        store.replace_rule(&old_hash, new_hash, new_form);
        rehashed += 1;
    }
    if rehashed > 0 {
        store
            .save(&store_path)
            .map_err(|e| miette::miette!("Failed to save trust store: {e}"))?;
    }
    Ok(rehashed)
}

/// Re-parse a stored canonical rule form and re-emit it with the
/// current canonicaliser. Returns `None` if the form fails to parse —
/// caller leaves such entries untouched.
fn recanonicalise_rule_form(form: &str) -> Option<String> {
    let (forms, errs) = may_i_sexpr::parse(form);
    if !errs.is_empty() {
        return None;
    }
    let sexpr = forms.into_iter().next()?;
    let rule = may_i_config::parse_rule(&sexpr).ok()?;
    Some(may_i_engine::trust::canonical_rule(&rule.value))
}

/// Emit a prominent warning naming any wrapper commands (sudo, xargs,
/// env, …) covered by user rules. The wrapper-boundary fix may change
/// these rules' behaviour even though the rule text is unchanged.
fn warn_about_wrapper_rules(config: &may_i_core::ast::Config) {
    const WRAPPERS: &[&str] = &[
        "sudo", "xargs", "env", "timeout", "nice", "time", "watch", "su", "ionice", "chrt", "mise",
        "find",
    ];
    let mut affected: Vec<&str> = Vec::new();
    for rule in &config.rules {
        if let may_i_core::ast::Effect::CommandPattern(pat) = &rule.command_effect.value {
            for program in may_i_engine::trust::extract_program_names(pat) {
                if WRAPPERS.contains(&program) && !affected.contains(&program) {
                    let canonical = WRAPPERS.iter().copied().find(|w| *w == program).unwrap();
                    affected.push(canonical);
                }
            }
        }
    }
    if affected.is_empty() {
        return;
    }
    let names = affected.join(", ");
    let bar = "━".repeat(72);
    eprintln!();
    eprintln!("{bar}");
    eprintln!("⚠ wrapper-boundary fix may change behaviour for rules covering:");
    eprintln!("    {names}");
    eprintln!();
    eprintln!("Run `may-i check` to verify your test cases still pass.");
    eprintln!("{bar}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_diff_with_changes() {
        let original = "(rule (command git) (effect :allow))\n";
        let migrated = "(rule git :effect :allow)\n";
        let path = Path::new("/home/user/.config/may-i/config.lisp");

        let diff = generate_diff(original, migrated, path, false);

        assert!(diff.contains("config.lisp"));
        assert!(diff.contains("-"));
        assert!(diff.contains("+"));
    }

    #[test]
    fn test_generate_diff_no_changes() {
        let original = "(rule git :effect :allow)\n";
        let path = Path::new("/home/user/.config/may-i/config.lisp");

        let diff = generate_diff(original, original, path, false);

        assert!(diff.is_empty());
    }

    #[test]
    fn test_generate_diff_with_colors() {
        let original = "(old)\n";
        let migrated = "(new)\n";
        let path = Path::new("/home/user/.config/may-i/config.lisp");

        let diff = generate_diff(original, migrated, path, true);

        assert!(diff.contains("config.lisp"));
        assert!(diff.contains("-"));
        assert!(diff.contains("+"));
    }

    #[test]
    fn test_generate_diff_without_colors() {
        let original = "(old)\n";
        let migrated = "(new)\n";
        let path = Path::new("/home/user/.config/may-i/config.lisp");

        let diff = generate_diff(original, migrated, path, false);

        assert!(diff.contains("config.lisp"));
        assert!(diff.contains("-"));
        assert!(diff.contains("+"));
        assert!(!diff.contains("\x1b["));
    }

    #[test]
    fn test_generate_diff_with_context() {
        let original = "line1\nline2\nline3\n(old)\nline5\nline6\nline7\n";
        let migrated = "line1\nline2\nline3\n(new)\nline5\nline6\nline7\n";
        let path = Path::new("test.lisp");

        let diff = generate_diff(original, migrated, path, false);

        assert!(diff.contains("line2"));
        assert!(diff.contains("line3"));
        assert!(diff.contains("line5"));
        assert!(diff.contains("line6"));
    }

    #[test]
    fn test_generate_diff_absolute_path() {
        let original = "(a)\n";
        let migrated = "(b)\n";
        let path = Path::new("/etc/may-i/config.lisp");

        let diff = generate_diff(original, migrated, path, false);

        assert!(diff.contains("/etc/may-i/config.lisp"));
    }

    #[test]
    fn test_generate_diff_home_path() {
        let original = "(a)\n";
        let migrated = "(b)\n";

        if let Ok(home) = std::env::var("HOME") {
            let home_path = Path::new(&home).join(".config/may-i/config.lisp");
            let diff = generate_diff(original, migrated, &home_path, false);

            assert!(diff.contains("~/.config/may-i/config.lisp"));
        }
    }
}

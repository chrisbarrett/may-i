// Migration command — convert v1 configs to canonical syntax.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use colored::Colorize;
use may_i_config::migrate::{migrate_forms, validate_migration};
use may_i_pp::detect_column_width;
use may_i_sexpr::parse_cst;
use similar::{ChangeTag, TextDiff};

use crate::output;

fn generate_diff(original: &str, migrated: &str, config_path: &Path, use_color: bool) -> String {
    let diff = TextDiff::from_lines(original, migrated);
    let mut output = String::new();

    let display_path = crate::output::shorten_home(config_path);
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

pub fn cmd_migrate(
    config_path: Option<&Path>,
    output: Option<&str>,
    yes: bool,
    dry_run: bool,
) -> miette::Result<()> {
    let config_file = may_i_config::resolve_path(config_path)?;

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
        // pretty_serialize_preserve formats constructed forms (the new
        // (when …), (cond …), etc. produced by migration) while preserving
        // user-written line breaks inside unchanged fill-eligible forms
        // like (or "cat" "bat" \n "find" "fd" ...). Canonical reformatting
        // belongs to `may-i fmt`, not `may-i migrate`.
        let column_width = detect_column_width(&source);
        let output_text = migrated_forms
            .iter()
            .map(|f| f.pretty_serialize_preserve(column_width))
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

    if !skipped_readonly.is_empty() {
        let term = output::Terminal::detect();
        output::render_skipped_readonly_advisory(&mut std::io::stderr(), &term, &skipped_readonly);
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
        let rehashed = crate::trust::rehash_after_migration()?;
        if rehashed > 0 {
            println!(
                "Rehashed {rehashed} trust entr{} to the new canonical form.",
                if rehashed == 1 { "y" } else { "ies" }
            );
        }

        // Class B warning: the carrier-boundary fix may change behaviour
        // for rules over sudo/xargs/etc. Re-load and scan the resolved
        // ruleset so users know to re-run their `(check …)` cases.
        if let Ok(loaded) = may_i_config::load_and_resolve(config_path) {
            warn_about_wrapper_rules(&loaded.config);
        }
    }

    Ok(())
}

/// Emit a warning advisory naming any carrier commands (sudo, xargs,
/// env, …) covered by user rules. The carrier-boundary fix may change
/// these rules' behaviour even though the rule text is unchanged.
fn warn_about_wrapper_rules(config: &may_i_core::ast::Config) {
    const WRAPPERS: &[&str] = &[
        "sudo", "xargs", "env", "timeout", "nice", "time", "watch", "su", "ionice", "chrt", "find",
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

    let term = output::Terminal::detect();
    output::render_wrapper_boundary_advisory(&mut std::io::stderr(), &term, &affected);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(safe-env-vars "A" "B")` migrates to `(env "A" (allow)) (env "B"
    /// (allow))` and the migrated text re-parses cleanly.
    #[test]
    fn safe_env_vars_migrates_to_env_allow_forms() {
        let (forms, errors) = parse_cst(r#"(safe-env-vars "A" "B")"#);
        assert!(errors.is_empty(), "{errors:?}");
        let migrated = migrate_forms(forms);
        let text = migrated
            .iter()
            .map(|f| f.serialize())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(text, "(env \"A\" (allow))\n(env \"B\" (allow))");
        // Re-parses cleanly and lowers to the same allowlist.
        let config = may_i_config::parse_config(&text).expect("migrated config parses");
        assert!(config.security.safe_env_vars.contains("A"));
        assert!(config.security.safe_env_vars.contains("B"));
        assert!(config.security.env_caps.is_empty());
    }

    /// Class A: the `:safe-env-vars` trust scope hashes identically before
    /// and after the migration, so a prior approval carries over without a
    /// rehash. Both spellings lower to the same allowlist and therefore the
    /// same canonical `(safe-env-vars …)` form.
    #[test]
    fn safe_env_vars_migration_preserves_trust_hash() {
        use may_i_engine::trust::compute_trust_views;

        let scope_hash = |src: &str| -> String {
            let mut config = may_i_config::parse_config(src).expect("parses");
            // The trust scope only materialises when entries are loaded.
            config.security.has_loaded_env_vars = true;
            let views = compute_trust_views(&config);
            views
                .iter()
                .find(|v| v.program == ":safe-env-vars")
                .map(|v| v.hash.clone())
                .expect(":safe-env-vars scope view present")
        };

        let before = scope_hash(r#"(safe-env-vars "A" "B")"#);
        let after = scope_hash(r#"(env "A" (allow)) (env "B" (allow))"#);
        assert_eq!(
            before, after,
            "migration must preserve the :safe-env-vars trust hash (Class A)"
        );
    }

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

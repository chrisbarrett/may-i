// Migration command — convert v1 configs to canonical syntax.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

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
) -> miette::Result<()> {
    let config_file = may_i_config::resolve_path(config_path)?;

    let source = std::fs::read_to_string(&config_file)
        .map_err(|e| miette::miette!("Failed to read config file: {e}"))?;

    let (original_forms, parse_errors) = parse_cst(&source);

    if let Some(err) = parse_errors.first() {
        return Err(may_i_config::ConfigError::from_raw(
            err.clone(),
            &source,
            &config_file.display().to_string(),
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

    let has_changes = source != output_text;

    if has_changes && !yes {
        let diff_output = generate_diff(&source, &output_text, &config_file, should_use_color());
        if !diff_output.is_empty() {
            println!("{}", diff_output);
        }

        let is_tty = io::stdin().is_terminal() && io::stdout().is_terminal();
        if !is_tty {
            // Output is piped — just show the diff as a preview.
            return Ok(());
        }

        let response = prompt_confirm("Apply migration? [y/N] ")
            .map_err(|e| miette::miette!("Failed to read prompt response: {e}"))?;

        if response.is_empty() || !response.to_lowercase().starts_with('y') {
            println!("Migration cancelled.");
            return Ok(());
        }
    }

    let output_path = output.map(Path::new);

    if let Some(path) = output_path {
        std::fs::write(path, output_text)
            .map_err(|e| miette::miette!("Failed to write output file: {e}"))?;
        println!("Migrated config written to {}", path.display());
    } else if has_changes {
        std::fs::write(&config_file, output_text)
            .map_err(|e| miette::miette!("Failed to write config file: {e}"))?;
        println!(
            "Migrated config written to {} (in-place)",
            config_file.display()
        );
    } else {
        println!("No migration needed - config is already up to date.");
    }

    Ok(())
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

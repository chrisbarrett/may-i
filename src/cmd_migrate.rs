//! Migration command for converting v1 configs to v2 syntax.
//!
//! This module implements the `may-i migrate` subcommand with interactive
//! prompting and simplified text-based diff display using the `similar` crate.
//!
//! # Interactive Mode
//!
//! When running in a TTY, the command shows a unified diff and prompts
//! for confirmation before applying changes. Use `--yes` to skip the prompt
//! for non-interactive usage (required in CI/CD).
//!
//! # Diff Format
//!
//! The diff display shows:
//! - File path header with `~` for HOME directory
//! - Removed lines prefixed with `-` (red in TTY mode)
//! - Added lines prefixed with `+` (green in TTY mode)
//! - 3 lines of context around changes
//!
//! # Error Handling
//!
//! Parse errors in the input file are returned with miette formatting,
//! showing line numbers and source context. Validation errors from the
//! v2 parser are similarly displayed with context from the output.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use colored::Colorize;
use may_i_config::v2::migrate::{migrate_forms, validate_migration};
use may_i_output::shorten_home;
use may_i_pp::detect_column_width;

use may_i_sexpr::parse_cst;
use similar::{ChangeTag, TextDiff};

/// Abstract terminal interaction behind a trait for testability.
pub trait PromptHandler {
    /// Check if the input/output is a TTY
    fn is_tty(&self) -> bool;
    /// Prompt the user for input
    fn prompt(&self, message: &str) -> io::Result<String>;
}

/// Real prompt handler that interacts with the actual terminal.
pub struct RealPromptHandler;

impl PromptHandler for RealPromptHandler {
    fn is_tty(&self) -> bool {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }

    fn prompt(&self, message: &str) -> io::Result<String> {
        print!("{}", message);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}

/// Mock prompt handler for testing.
#[cfg(test)]
pub struct MockPromptHandler {
    responses: Vec<String>,
    response_index: std::cell::RefCell<usize>,
    is_tty: bool,
}

#[cfg(test)]
impl MockPromptHandler {
    pub fn new(responses: Vec<String>, is_tty: bool) -> Self {
        Self {
            responses,
            response_index: std::cell::RefCell::new(0),
            is_tty,
        }
    }
}

#[cfg(test)]
impl PromptHandler for MockPromptHandler {
    fn is_tty(&self) -> bool {
        self.is_tty
    }

    fn prompt(&self, _message: &str) -> io::Result<String> {
        let idx = *self.response_index.borrow();
        if idx < self.responses.len() {
            *self.response_index.borrow_mut() += 1;
            Ok(self.responses[idx].clone())
        } else {
            Ok("".to_string())
        }
    }
}

/// Generate a unified text diff between original and migrated content.
///
/// The diff includes:
/// - File path header with `~` for HOME directory
/// - Removed lines with `-` prefix
/// - Added lines with `+` prefix
/// - 3 lines of context around changes
/// - Colors when stdout is TTY and NO_COLOR is not set
fn generate_diff(original: &str, migrated: &str, config_path: &Path, use_color: bool) -> String {
    let diff = TextDiff::from_lines(original, migrated);
    let mut output = String::new();

    // Add file path header
    let display_path = shorten_home(config_path);
    output.push_str(&format!("{}:\n", display_path));

    // Track if we've seen any changes
    let mut has_changes = false;

    // Generate diff with context
    for group in diff.grouped_ops(3) {
        for op in group {
            for change in diff.iter_changes(&op) {
                has_changes = true;
                let change_tag: ChangeTag = change.tag();
                let (prefix, line) = match change_tag {
                    ChangeTag::Delete => {
                        let line = change.value().trim_end_matches('\n');
                        if use_color {
                            ("-".red().to_string(), line.red().to_string())
                        } else {
                            ("-".to_string(), line.to_string())
                        }
                    }
                    ChangeTag::Insert => {
                        let line = change.value().trim_end_matches('\n');
                        if use_color {
                            ("+".green().to_string(), line.green().to_string())
                        } else {
                            ("+".to_string(), line.to_string())
                        }
                    }
                    ChangeTag::Equal => {
                        let line = change.value().trim_end_matches('\n');
                        (" ".to_string(), line.to_string())
                    }
                };
                output.push_str(&format!("{}{}\n", prefix, line));
            }
        }
    }

    if has_changes { output } else { String::new() }
}

/// Check if color output should be used.
///
/// Returns true only if:
/// - stdout is a TTY
/// - NO_COLOR environment variable is not set
fn should_use_color() -> bool {
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    io::stdout().is_terminal()
}

/// Run the migration command.
pub fn cmd_migrate(
    config_path: Option<&Path>,
    output: Option<&str>,
    yes: bool,
) -> miette::Result<()> {
    let handler = RealPromptHandler;
    cmd_migrate_with_handler(config_path, output, yes, &handler)
}

/// Run the migration command with a custom prompt handler (for testing).
pub fn cmd_migrate_with_handler(
    config_path: Option<&Path>,
    output: Option<&str>,
    yes: bool,
    handler: &dyn PromptHandler,
) -> miette::Result<()> {
    // Resolve config file path using the same mechanism as other commands
    let config_file = may_i_config::resolve_path(config_path)?;

    // Read input from the resolved config file
    let source = std::fs::read_to_string(&config_file)
        .map_err(|e| miette::miette!("Failed to read config file: {e}"))?;

    // Parse the source into CST nodes
    let (original_forms, parse_errors) = parse_cst(&source);

    // Handle parse errors
    if !parse_errors.is_empty()
        && let Some(err) = parse_errors.first()
    {
        return Err(may_i_config::ConfigError::from_raw(
            err.clone(),
            &source,
            &config_file.display().to_string(),
        )
        .into());
    }

    // Migrate the forms
    let migrated_forms = migrate_forms(original_forms.clone());

    // Detect appropriate column width from existing code style
    let column_width = detect_column_width(&source);

    // Generate pretty-printed output preserving comments
    let output_text = migrated_forms
        .iter()
        .map(|f| f.pretty_serialize(column_width))
        .collect::<Vec<_>>()
        .join("");

    // Validate migration output parses with v2 parser
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

    // Check if there are any changes by comparing serialized output
    let has_changes = source != output_text;

    // Show diff if changes exist and not auto-confirmed
    if has_changes && !yes {
        let use_color = should_use_color();
        let diff_output = generate_diff(&source, &output_text, &config_file, use_color);
        if !diff_output.is_empty() {
            println!("{}", diff_output);
        }
    }

    // Check if we need to prompt for confirmation
    if has_changes && !yes {
        if !handler.is_tty() {
            return Err(miette::miette!(
                "Config file would be modified. Use --yes to confirm non-interactive execution."
            ));
        }

        let response = handler
            .prompt("Apply migration? [y/N] ")
            .map_err(|e| miette::miette!("Failed to read prompt response: {e}"))?;

        // Default to No (cancel) if user just presses Enter
        if response.is_empty() || !response.to_lowercase().starts_with('y') {
            println!("Migration cancelled.");
            return Ok(());
        }
    }

    // Determine output path
    let output_path = output.map(Path::new);

    // Write output or print
    if let Some(path) = output_path {
        std::fs::write(path, output_text)
            .map_err(|e| miette::miette!("Failed to write output file: {e}"))?;
        println!("Migrated config written to {}", path.display());
    } else if has_changes {
        // In-place migration
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
    fn test_real_prompt_handler_is_tty() {
        // This test just ensures the handler compiles and basic behavior works
        let handler = RealPromptHandler;
        // Can't reliably test is_tty in tests, but we can verify it doesn't panic
        let _ = handler.is_tty();
    }

    #[test]
    fn test_mock_prompt_handler() {
        let handler = MockPromptHandler::new(vec!["yes".to_string(), "no".to_string()], true);

        assert!(handler.is_tty());
        assert_eq!(handler.prompt("Test: ").unwrap(), "yes");
        assert_eq!(handler.prompt("Test: ").unwrap(), "no");
        assert_eq!(handler.prompt("Test: ").unwrap(), ""); // Exhausted responses
    }

    #[test]
    fn test_should_use_color_respects_no_color() {
        // Save original value
        let original = std::env::var("NO_COLOR").ok();

        // Test with NO_COLOR set
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        assert!(!should_use_color());

        // Test with NO_COLOR unset
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        // Result depends on whether stdout is a TTY in test environment
        let _ = should_use_color();

        // Restore original value
        unsafe {
            match original {
                Some(val) => std::env::set_var("NO_COLOR", val),
                None => std::env::remove_var("NO_COLOR"),
            }
        }
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

        // Test with colors enabled
        let diff = generate_diff(original, migrated, path, true);

        assert!(diff.contains("config.lisp"));
        assert!(diff.contains("-"));
        assert!(diff.contains("+"));
        // When use_color=true, the function attempts to colorize
        // (actual ANSI codes depend on the colored crate's behavior in test env)
    }

    #[test]
    fn test_generate_diff_without_colors() {
        let original = "(old)\n";
        let migrated = "(new)\n";
        let path = Path::new("/home/user/.config/may-i/config.lisp");

        // Test with colors disabled
        let diff = generate_diff(original, migrated, path, false);

        assert!(diff.contains("config.lisp"));
        assert!(diff.contains("-"));
        assert!(diff.contains("+"));
        // No ANSI color codes
        assert!(!diff.contains("\x1b["));
    }

    #[test]
    fn test_generate_diff_with_context() {
        let original = "line1\nline2\nline3\n(old)\nline5\nline6\nline7\n";
        let migrated = "line1\nline2\nline3\n(new)\nline5\nline6\nline7\n";
        let path = Path::new("test.lisp");

        let diff = generate_diff(original, migrated, path, false);

        // Should have context lines
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

        // Should show absolute path (no ~ substitution since it's outside HOME)
        assert!(diff.contains("/etc/may-i/config.lisp"));
    }

    #[test]
    fn test_generate_diff_home_path() {
        let original = "(a)\n";
        let migrated = "(b)\n";

        // Create a path that looks like it's in home directory
        if let Ok(home) = std::env::var("HOME") {
            let home_path = Path::new(&home).join(".config/may-i/config.lisp");
            let diff = generate_diff(original, migrated, &home_path, false);

            // Should show ~ prefix
            assert!(diff.contains("~/.config/may-i/config.lisp"));
        }
    }

    #[test]
    fn test_should_use_color_no_color_set() {
        // Save original
        let original = std::env::var("NO_COLOR").ok();

        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        assert!(!should_use_color());

        // Restore
        unsafe {
            match original {
                Some(val) => std::env::set_var("NO_COLOR", val),
                None => std::env::remove_var("NO_COLOR"),
            }
        }
    }

    #[test]
    fn test_mock_handler_tty_false() {
        let handler = MockPromptHandler::new(vec!["y".to_string()], false);
        assert!(!handler.is_tty());
    }
}

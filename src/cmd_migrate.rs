//! Migration command for converting v1 configs to v2 syntax.
//!
//! This module implements the `may-i migrate` subcommand with interactive
//! prompting and detailed diff display.
//!
//! # Interactive Mode
//!
//! When running in a TTY, the command shows a form-by-form diff and prompts
//! for confirmation before applying changes. Use `--yes` to skip the prompt
//! for non-interactive usage (required in CI/CD).
//!
//! # Diff Layout
//!
//! The diff display adapts to terminal width:
//! - ≥80 columns: Side-by-side layout showing before/after
//! - <80 columns: Vertical layout showing before then after
//!
//! # Error Handling
//!
//! Parse errors in the input file are returned with miette formatting,
//! showing line numbers and source context. Validation errors from the
//! v2 parser are similarly displayed with context from the output.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use may_i_config::v2::migrate::{migrate_forms, validate_migration};
use may_i_output::diff_renderer::{DiffConfig, display_with_pager, render_diff, should_use_pager};
use may_i_sexpr::diff::compute_diff;
use may_i_sexpr::parse_cst;

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

    // Serialize original forms for comparison (before migration)
    let original_text: String = original_forms
        .iter()
        .map(|f| f.serialize())
        .collect::<Vec<_>>()
        .join("");

    // Migrate the forms
    let migrated_forms = migrate_forms(original_forms.clone());

    // Generate output text
    let output_text = migrated_forms
        .iter()
        .map(|f| f.serialize())
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

    // Compute diff between original and migrated
    let original_flat: Vec<_> = original_forms.into_iter().map(|b| *b).collect();
    let migrated_flat: Vec<_> = migrated_forms.into_iter().map(|b| *b).collect();
    let diff_nodes = compute_diff(original_flat, migrated_flat);

    // Check if there are any changes by comparing serialized output
    // This avoids showing diffs for formatting-only changes
    let has_changes = original_text != output_text;

    // Show diff if requested or if changes exist and not auto-confirmed
    if has_changes && !yes {
        let config = DiffConfig::default();
        let diff_output = render_diff(&diff_nodes, &config);

        // Determine if we should use the pager
        let use_pager = should_use_pager(diff_output.lines().count());

        // Display with pager if appropriate
        if let Err(e) = display_with_pager(&diff_output, use_pager) {
            eprintln!("Warning: Failed to display with pager: {e}");
            println!("{}", diff_output);
        }
    }

    // Check if we need to prompt for confirmation
    if has_changes && !yes {
        if !handler.is_tty() {
            return Err(miette::miette!(
                "Migration would modify {} form(s). Use --yes to confirm non-interactive execution.",
                diff_nodes
                    .iter()
                    .filter(|n| !n.ann.change.is_unchanged())
                    .count()
            ));
        }

        let response = handler
            .prompt("Apply migration? [Y/n] ")
            .map_err(|e| miette::miette!("Failed to read prompt response: {e}"))?;

        if !response.is_empty() && !response.to_lowercase().starts_with('y') {
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
}

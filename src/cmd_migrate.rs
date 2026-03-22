// Migration command for converting v1 configs to v2 syntax.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use may_i_config::v2::migrate::{migrate_forms, validate_migration};
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

/// Render migration diffs with side-by-side or vertical layout.
fn render_diff(
    analysis: &may_i_config::v2::migrate::MigrationAnalysis,
    term_width: usize,
) -> String {
    use colored::Colorize;

    let mut output = String::new();

    // Render errors first if any
    if !analysis.errors.is_empty() {
        output.push_str(&format!("\n{}", "Parse Errors:".bold().red()));
        output.push_str(&format!("\n{}", "─".repeat(term_width.min(80)).dimmed()));

        for error in &analysis.errors {
            output.push_str(&format!("\n{}: {}", "Error".red().bold(), error.message));

            // Show context before
            for ctx in &error.context_before {
                output.push_str(&format!("  {}\n", ctx.dimmed()));
            }

            // Show error indicator
            if error.span.start > 0 || error.span.end > 0 {
                output.push_str(&format!(
                    "  {}\n",
                    "^".repeat(error.span.end.saturating_sub(error.span.start))
                        .red()
                ));
            }

            // Show context after
            for ctx in &error.context_after {
                output.push_str(&format!("  {}\n", ctx.dimmed()));
            }
        }

        output.push_str(&format!("\n{}", "─".repeat(term_width.min(80)).dimmed()));
    }

    if analysis.diffs.is_empty() {
        output.push_str("\nNo changes needed.\n");
        return output;
    }

    output.push_str(&format!("\n{}", "Migration Diff:".bold()));
    output.push_str(&format!("\n{}", "─".repeat(term_width.min(80)).dimmed()));

    for (i, diff) in analysis.diffs.iter().enumerate() {
        if i > 0 {
            output.push_str("\n\n");
        }

        // Render context before
        for ctx in &diff.context_before {
            output.push_str(&format!("{}", ctx.dimmed()));
        }

        // Render the form change
        if term_width >= 80 {
            // Side-by-side layout
            render_side_by_side(&mut output, diff, term_width);
        } else {
            // Vertical layout
            render_vertical(&mut output, diff);
        }

        // Render context after
        for ctx in &diff.context_after {
            output.push_str(&format!("{}", ctx.dimmed()));
        }
    }

    output.push_str(&format!("\n{}", "─".repeat(term_width.min(80)).dimmed()));
    output.push_str(&format!(
        "\n{} forms will change, {} unchanged\n",
        analysis.diffs.len().to_string().yellow(),
        analysis.unchanged_count.to_string().dimmed()
    ));

    output
}

/// Render diff in side-by-side layout.
fn render_side_by_side(
    output: &mut String,
    diff: &may_i_config::v2::migrate::MigrationDiff,
    term_width: usize,
) {
    use colored::Colorize;

    let separator = " │ ";
    let available_width = term_width.saturating_sub(separator.len() + 2);
    let column_width = available_width / 2;

    let before_lines: Vec<_> = diff.before.lines().collect();
    let after_lines: Vec<_> = diff.after.lines().collect();
    let max_lines = before_lines.len().max(after_lines.len());

    for i in 0..max_lines {
        let before = before_lines.get(i).unwrap_or(&"");
        let after = after_lines.get(i).unwrap_or(&"");

        let before_trunc = truncate_visible(before, column_width);
        let after_trunc = truncate_visible(after, column_width);

        let before_colored = if before != after {
            before_trunc.red().to_string()
        } else {
            before_trunc.to_string()
        };

        let after_colored = if before != after {
            after_trunc.green().to_string()
        } else {
            after_trunc.to_string()
        };

        output.push_str(&format!(
            "\n{:width$}{}{}",
            before_colored,
            separator,
            after_colored,
            width = column_width + 10 // Account for ANSI codes
        ));
    }
}

/// Render diff in vertical layout.
fn render_vertical(output: &mut String, diff: &may_i_config::v2::migrate::MigrationDiff) {
    use colored::Colorize;

    output.push_str(&format!("\n{}\n", "BEFORE:".red()));
    for line in diff.before.lines() {
        output.push_str(&format!("  {}\n", line.red()));
    }

    output.push_str(&format!("{}\n", "AFTER:".green()));
    for line in diff.after.lines() {
        output.push_str(&format!("  {}\n", line.green()));
    }
}

/// Truncate a string to a visible width, accounting for ANSI codes.
fn truncate_visible(s: &str, max_width: usize) -> String {
    let visible_len = s.chars().count();
    if visible_len <= max_width {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_width.saturating_sub(1)).collect();
        format!("{}…", truncated)
    }
}

/// Run the migration command.
pub fn cmd_migrate(
    config_path: Option<&Path>,
    output: Option<&str>,
    dry_run: bool,
    diff: bool,
    no_validate: bool,
    yes: bool,
) -> miette::Result<()> {
    let handler = RealPromptHandler;
    cmd_migrate_with_handler(
        config_path,
        output,
        dry_run,
        diff,
        no_validate,
        yes,
        &handler,
    )
}

/// Run the migration command with a custom prompt handler (for testing).
pub fn cmd_migrate_with_handler(
    config_path: Option<&Path>,
    output: Option<&str>,
    dry_run: bool,
    diff: bool,
    no_validate: bool,
    yes: bool,
    handler: &dyn PromptHandler,
) -> miette::Result<()> {
    // Resolve config file path using the same mechanism as other commands
    let config_file = may_i_config::resolve_path(config_path)?;

    // Read input from the resolved config file
    let source = std::fs::read_to_string(&config_file)
        .map_err(|e| miette::miette!("Failed to read config file: {e}"))?;

    // Analyze the migration
    let analysis = may_i_config::v2::migrate::analyze_migration(&source);

    // Handle parse errors - cannot proceed with migration if source has syntax errors
    if !analysis.errors.is_empty() {
        // Return the first error with full miette formatting against the input file
        if let Some(err) = analysis.errors.first() {
            return Err(may_i_config::ConfigError::from_raw(
                may_i_sexpr::RawError::new(
                    &err.message,
                    may_i_core::Span::new(err.span.start, err.span.end),
                ),
                &source,
                &config_file.display().to_string(),
            )
            .into());
        }
    }

    // Check for unhandled v1 constructs
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

    // Generate migrated output
    let output_text = if analysis.diffs.is_empty() {
        source.clone() // No changes needed
    } else {
        // Re-parse and migrate to get the output
        let (forms, _) = parse_cst(&source);
        let migrated = migrate_forms(forms);
        migrated
            .iter()
            .map(|f| f.serialize())
            .collect::<Vec<_>>()
            .join("")
    };

    // Validate migration output parses with v2 parser
    if !no_validate && let Err(validation_errors) = validate_migration(&output_text) {
        // The migrated output cannot be parsed by the v2 parser.
        // Return the validation error with context from the output.
        if let Some(raw_err) = validation_errors.first() {
            return Err(may_i_config::ConfigError::from_raw(
                raw_err.clone(),
                &output_text,
                "<migrated-output>",
            )
            .into());
        }
    }

    // Get terminal width for rendering
    let term_width = get_term_width();

    // Show diff if requested or if changes exist
    if diff || (!analysis.diffs.is_empty() && !yes) {
        let diff_output = render_diff(&analysis, term_width);
        println!("{}", diff_output);
    }

    // Check if we need to prompt for confirmation
    if !analysis.diffs.is_empty() && !dry_run && !yes {
        if !handler.is_tty() {
            return Err(miette::miette!(
                "Migration would modify {} form(s). Use --yes to confirm non-interactive execution.",
                analysis.diffs.len()
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

    // Determine output path: use provided output, or default to the input config file for in-place migration
    let output_path = output.map(Path::new);

    // Write output or print
    if dry_run {
        if analysis.diffs.is_empty() {
            println!("\nDry run - no changes needed.");
        } else {
            println!("\nDry run - would produce:");
            println!("{}", output_text);
        }
    } else if let Some(path) = output_path {
        std::fs::write(path, output_text)
            .map_err(|e| miette::miette!("Failed to write output file: {e}"))?;
        println!("Migrated config written to {}", path.display());
    } else if !analysis.diffs.is_empty() {
        // In-place migration: write back to the source config file
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

/// Get terminal width, with fallback to 80.
fn get_term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80)
}

//! Diff rendering for migration output.
//!
//! This module provides pretty-printed diff display with two-column layout,
//! fold markers for unchanged sections, and terminal width adaptation.

use std::io::IsTerminal;

use colored::Colorize;
use may_i_core::Doc;
use may_i_pp::{Format, pretty};
use may_i_sexpr::diff::{ChangeType, DiffCst, PlainCst};

/// Configuration for diff rendering.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Whether to show line numbers in the left gutter.
    pub line_numbers: bool,
    /// Terminal width threshold for two-column layout.
    pub two_column_threshold: usize,
    /// String to use as fold marker for collapsed sections.
    pub fold_marker: String,
    /// Number of context lines to show around changes.
    pub show_context_lines: usize,
    /// Whether to use colors in output.
    pub color: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            line_numbers: true,
            two_column_threshold: 80,
            fold_marker: "⋮".to_string(),
            show_context_lines: 2,
            color: true,
        }
    }
}

/// A line in the diff output.
#[derive(Debug, Clone)]
pub enum DiffLine {
    /// A blank line (for spacing).
    Blank,
    /// A fold marker indicating collapsed unchanged content.
    FoldMarker,
    /// A separator line (horizontal rule).
    Separator,
    /// Header showing "BEFORE | AFTER".
    Header,
    /// A line showing content from both columns.
    Content {
        /// Line number in the original file (if applicable).
        line_num: Option<usize>,
        /// Content for the "before" column.
        before: String,
        /// Content for the "after" column.
        after: String,
        /// Whether this line represents a change.
        is_changed: bool,
    },
}

/// Render a diff as a string.
///
/// # Arguments
///
/// * `annotated` - The diff-annotated CST nodes.
/// * `config` - Rendering configuration.
///
/// # Returns
///
/// A rendered string ready for display.
pub fn render_diff(annotated: &[DiffCst], config: &DiffConfig) -> String {
    let term_width = get_term_width();
    let use_two_column = term_width >= config.two_column_threshold;

    if use_two_column {
        render_two_column(annotated, config, term_width)
    } else {
        render_inline(annotated, config)
    }
}

/// Render diff in two-column layout (before | after).
fn render_two_column(annotated: &[DiffCst], config: &DiffConfig, term_width: usize) -> String {
    let mut output = String::new();

    // Calculate column widths
    // Note: line numbers are disabled for now since we don't track them in Span
    let _line_num_width = 0;
    let gutter_width = 0;
    let separator_width = 3; // " │ "
    let available_width = term_width.saturating_sub(gutter_width + separator_width + 2);
    let column_width = available_width / 2;

    // Add header
    if config.color {
        output.push_str(&format!(
            "{:gutter$}{:>cw$} │ {:<cw$}\n",
            "",
            "BEFORE".bold(),
            "AFTER".bold(),
            gutter = gutter_width,
            cw = column_width
        ));
    } else {
        output.push_str(&format!(
            "{:gutter$}{:>cw$} │ {:<cw$}\n",
            "",
            "BEFORE",
            "AFTER",
            gutter = gutter_width,
            cw = column_width
        ));
    }
    output.push_str(&"─".repeat(term_width));
    output.push('\n');

    // Group forms and render
    let lines = build_diff_lines(annotated, config);
    let mut prev_was_fold = false;

    for line in lines {
        match line {
            DiffLine::Blank => {
                output.push('\n');
                prev_was_fold = false;
            }
            DiffLine::FoldMarker => {
                if !prev_was_fold {
                    let marker = if config.color {
                        config.fold_marker.dimmed().to_string()
                    } else {
                        config.fold_marker.clone()
                    };
                    let padding = (term_width - 1) / 2;
                    output.push_str(&format!("{:padding$}{}\n", "", marker, padding = padding));
                    prev_was_fold = true;
                }
            }
            DiffLine::Separator => {
                output.push_str(&"─".repeat(term_width));
                output.push('\n');
                prev_was_fold = false;
            }
            DiffLine::Header => {
                // Header already added above
                prev_was_fold = false;
            }
            DiffLine::Content {
                line_num: _,
                before,
                after,
                is_changed,
            } => {
                let before_colored = if is_changed && config.color {
                    before.red().to_string()
                } else {
                    before
                };
                let after_colored = if is_changed && config.color {
                    after.green().to_string()
                } else {
                    after
                };

                // Format line number
                let _line_prefix = String::new(); // Line numbers disabled for now

                // Truncate columns to fit
                let before_trunc = truncate_width(&before_colored, column_width);
                let after_trunc = truncate_width(&after_colored, column_width);

                output.push_str(&format!(
                    "{:cw$} │ {}\n",
                    before_trunc,
                    after_trunc,
                    cw = column_width
                ));
                prev_was_fold = false;
            }
        }
    }

    output
}

/// Render diff in inline/vertical layout (for narrow terminals).
fn render_inline(annotated: &[DiffCst], config: &DiffConfig) -> String {
    let mut output = String::new();

    for node in annotated {
        match &node.ann.change {
            ChangeType::Unchanged => {
                // Skip unchanged forms in inline mode, or show with fold marker
                continue;
            }
            ChangeType::Modified { after } => {
                if config.color {
                    output.push_str(&format!("{}\n", "BEFORE:".red().bold()));
                } else {
                    output.push_str("BEFORE:\n");
                }
                // Convert DiffCst to PlainCst for printing
                let plain_before = diff_to_plain(node);
                output.push_str(&pretty_print_node(&plain_before, config));
                output.push('\n');

                if config.color {
                    output.push_str(&format!("{}\n", "AFTER:".green().bold()));
                } else {
                    output.push_str("AFTER:\n");
                }
                output.push_str(&pretty_print_node(after, config));
                output.push('\n');
            }
            ChangeType::Deleted => {
                if config.color {
                    output.push_str(&format!("{}\n", "DELETED:".red().bold()));
                } else {
                    output.push_str("DELETED:\n");
                }
                // Convert DiffCst to PlainCst for printing
                let plain = diff_to_plain(node);
                output.push_str(&pretty_print_node(&plain, config));
                output.push('\n');
            }
        }
    }

    output
}

/// Build diff lines from annotated CST nodes.
fn build_diff_lines(annotated: &[DiffCst], config: &DiffConfig) -> Vec<DiffLine> {
    let mut lines = Vec::new();
    let mut unchanged_streak = 0;

    for (idx, node) in annotated.iter().enumerate() {
        let is_changed = !node.ann.change.is_unchanged();

        if is_changed {
            // Flush any pending unchanged streak with fold marker
            if unchanged_streak > config.show_context_lines * 2 {
                lines.push(DiffLine::FoldMarker);
            }
            unchanged_streak = 0;

            // Add the changed form
            match &node.ann.change {
                ChangeType::Unchanged => unreachable!(),
                ChangeType::Modified { after } => {
                    // Pretty-print both versions
                    let plain_before = diff_to_plain(node);
                    let before_pp = pretty_print_node(&plain_before, config);
                    let after_pp = pretty_print_node(after, config);

                    // Split into lines and pair them up
                    let before_lines: Vec<_> = before_pp.lines().collect();
                    let after_lines: Vec<_> = after_pp.lines().collect();
                    let max_lines = before_lines.len().max(after_lines.len());

                    for i in 0..max_lines {
                        lines.push(DiffLine::Content {
                            line_num: None, // Line numbers disabled for now
                            before: before_lines.get(i).unwrap_or(&"").to_string(),
                            after: after_lines.get(i).unwrap_or(&"").to_string(),
                            is_changed: true,
                        });
                    }
                }
                ChangeType::Deleted => {
                    let plain = diff_to_plain(node);
                    let before_pp = pretty_print_node(&plain, config);

                    for line in before_pp.lines() {
                        lines.push(DiffLine::Content {
                            line_num: None,
                            before: line.to_string(),
                            after: "".to_string(),
                            is_changed: true,
                        });
                    }
                }
            }
        } else {
            unchanged_streak += 1;

            // Show context lines around unchanged sections
            if unchanged_streak <= config.show_context_lines
                || idx == annotated.len() - 1 && unchanged_streak <= config.show_context_lines * 2
            {
                let plain = diff_to_plain(node);
                let pp = pretty_print_node(&plain, config);

                for line in pp.lines() {
                    lines.push(DiffLine::Content {
                        line_num: None,
                        before: line.to_string(),
                        after: line.to_string(),
                        is_changed: false,
                    });
                }
            }
        }
    }

    lines
}

/// Pretty-print a CST node using the pp crate.
fn pretty_print_node(node: &PlainCst, config: &DiffConfig) -> String {
    // Convert CST to Doc
    let doc = cst_to_doc(node);

    // Pretty-print with appropriate width
    let fmt = Format {
        width: 72,
        color: config.color,
        line_number: None,
    };

    pretty(&doc, 0, &fmt)
}

/// Convert a CST node to a Doc for pretty-printing.
fn cst_to_doc(node: &PlainCst) -> Doc {
    match &node.shape {
        may_i_sexpr::cst::ShapeF::Atom(s) => Doc::atom(s.clone()),
        may_i_sexpr::cst::ShapeF::Str(s) => Doc::atom(format!("\"{}\"", s)),
        may_i_sexpr::cst::ShapeF::List(children) => {
            let child_docs: Vec<Doc> = children.iter().map(|c| cst_to_doc(c)).collect();
            Doc::list(child_docs)
        }
        may_i_sexpr::cst::ShapeF::Vector(children) => {
            let child_docs: Vec<Doc> = children.iter().map(|c| cst_to_doc(c)).collect();
            Doc::vector(child_docs)
        }
    }
}

/// Convert a DiffCst to PlainCst by extracting the trivia annotation.
fn diff_to_plain(diff_node: &DiffCst) -> PlainCst {
    PlainCst {
        ann: diff_node.ann.trivia.clone(),
        shape: diff_node
            .shape
            .map_ref(|child| Box::new(diff_to_plain(child))),
    }
}

/// Truncate a string to a visible width.
fn truncate_width(s: &str, max_width: usize) -> String {
    let visible_len = visible_width(s);
    if visible_len <= max_width {
        s.to_string()
    } else {
        // Find the byte position to truncate at
        let mut width = 0;
        let mut result = String::new();
        for ch in s.chars() {
            let ch_width = if ch == '\x1b' {
                // Skip ANSI escape sequences
                0
            } else if ch.is_ascii() {
                1
            } else {
                2 // Assume non-ASCII chars are wide
            };
            if width + ch_width > max_width - 1 {
                result.push('…');
                break;
            }
            result.push(ch);
            width += ch_width;
        }
        result
    }
}

/// Calculate visible width of a string (ignoring ANSI codes).
fn visible_width(s: &str) -> usize {
    let mut width = 0;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            // Use 1 for ASCII, 2 for CJK/fullwidth chars
            width += if ch.is_ascii() { 1 } else { 2 };
        }
    }
    width
}

/// Get terminal width with fallback.
fn get_term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80)
}

/// Display content using an interactive pager when appropriate.
///
/// # Arguments
///
/// * `content` - The content to display
/// * `use_pager` - Whether to use the pager (only if stdout is a TTY)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the pager fails.
pub fn display_with_pager(
    content: &str,
    use_pager: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let is_tty = stdout.is_terminal();

    if use_pager && is_tty {
        // Use minus pager for interactive display
        let pager = minus::Pager::new();
        pager.set_text(content)?;
        minus::page_all(pager)?;
    } else {
        // Direct output for piping or when pager is disabled
        println!("{}", content);
    }

    Ok(())
}

/// Check if the output should use a pager based on content length.
///
/// Returns true if the content exceeds terminal height and we're in a TTY.
pub fn should_use_pager(content_lines: usize) -> bool {
    let stdout = std::io::stdout();
    if !stdout.is_terminal() {
        return false;
    }

    // Get terminal height
    let term_height = terminal_size::terminal_size()
        .map(|(_, h)| h.0 as usize)
        .unwrap_or(24);

    // Use pager if content exceeds terminal height
    content_lines > term_height
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_width() {
        assert_eq!(truncate_width("hello", 10), "hello");
        assert_eq!(truncate_width("hello world", 5), "hell…");
    }

    #[test]
    fn test_visible_width() {
        assert_eq!(visible_width("hello"), 5);
        assert_eq!(visible_width("\x1b[31mhello\x1b[0m"), 5);
    }

    #[test]
    fn test_diff_config_default() {
        let config = DiffConfig::default();
        assert!(config.line_numbers);
        assert_eq!(config.two_column_threshold, 80);
        assert_eq!(config.fold_marker, "⋮");
        assert_eq!(config.show_context_lines, 2);
        assert!(config.color);
    }

    #[test]
    fn test_display_with_pager_direct_output() {
        // Test that display_with_pager works in non-pager mode
        let result = display_with_pager("test content", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_should_use_pager_small_content() {
        // Small content should not use pager
        assert!(!should_use_pager(5));
    }

    #[test]
    fn test_should_use_pager_large_content() {
        // Large content might use pager (depends on terminal)
        // This test mainly ensures the function doesn't panic
        let _ = should_use_pager(1000);
    }
}

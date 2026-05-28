// Intent: render the "trusted programs grouped by source file" listing used
// by `cmd_trust`. Each section is a dimmed file heading with the
// comma-joined program names wrapped underneath at terminal width.
//
// `TrustListing` is the per-subcommand builder; the leaf renderer below is
// crate-private and reachable only through it.

use std::io::Write;
use std::path::Path;

use colored::Colorize;
use may_i_output::{ColItem, Layout};

use super::{Terminal, shorten_home, write_layout};

/// Per-subcommand text-output builder for the trusted-programs listing in
/// `may-i trust`. Owns the optional dimmed heading and the grouped rows.
pub struct TrustListing<'a> {
    pub heading: Option<&'a str>,
    pub groups: &'a [(&'a Path, Vec<&'a str>)],
}

impl TrustListing<'_> {
    /// Emit the optional heading followed by the grouped sections to `w`.
    pub fn render(&self, w: &mut impl Write, term: &Terminal) {
        if let Some(h) = self.heading {
            let _ = writeln!(w, "  {}", h.dimmed());
        }
        render_trusted_groups(w, term, self.groups);
    }
}

/// Render groups to `w` at outer indent 2. Each section is a dimmed file
/// heading followed by the program names wrapped under it.
fn render_trusted_groups(w: &mut impl Write, term: &Terminal, groups: &[(&Path, Vec<&str>)]) {
    let mut sections: Vec<Layout> = Vec::new();
    for (i, (file, progs)) in groups.iter().enumerate() {
        if i > 0 {
            sections.push(Layout::Blank);
        }
        let heading = Layout::Text(shorten_home(file).dimmed().to_string());
        let items: Vec<ColItem> = progs.iter().map(|p| ColItem::new(*p, p.len())).collect();
        let programs = Layout::Indent(
            2,
            Box::new(Layout::Wrap {
                items,
                separator: ColItem::new(", ", 2),
            }),
        );
        sections.push(Layout::Stack(vec![heading, programs]));
    }
    let layout = Layout::Indent(2, Box::new(Layout::Stack(sections)));
    write_layout(w, &layout, term);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::strip_ansi;

    fn render_listing_at(
        width: usize,
        heading: Option<&str>,
        groups: &[(&Path, Vec<&str>)],
    ) -> String {
        temp_env::with_var("COLUMNS", Some(width.to_string()), || {
            let term = Terminal::new(width);
            let mut buf = Vec::new();
            TrustListing { heading, groups }.render(&mut buf, &term);
            strip_ansi(&String::from_utf8(buf).unwrap())
        })
    }

    fn render_listing(heading: Option<&str>, groups: &[(&Path, Vec<&str>)]) -> String {
        render_listing_at(80, heading, groups)
    }

    #[test]
    fn trust_listing_emits_groups_without_heading() {
        let path_a = Path::new("/tmp/a.lisp");
        let path_b = Path::new("/tmp/b.lisp");
        let groups = vec![(path_a, vec!["git", "hg"]), (path_b, vec!["jj"])];
        insta::assert_snapshot!(render_listing(None, &groups));
    }

    #[test]
    fn trust_listing_emits_heading_before_groups() {
        let path = Path::new("/tmp/rules.lisp");
        let groups = vec![(path, vec!["git"])];
        insta::assert_snapshot!(render_listing(Some("Trusted:"), &groups));
    }

    #[test]
    fn wide_row_wraps_under_heading_and_respects_terminal_width() {
        let width = 60;
        let path = Path::new("/tmp/wide.lisp");
        // Long program names; comma-joined far exceeds 60 cols.
        let progs = vec![
            "./scripts/test-affected.sh",
            "./scripts/affected-tests.sh",
            "./scripts/run-tests.sh",
            "./scripts/lint-everything.sh",
            "./scripts/format-everything.sh",
        ];
        let groups = vec![(path, progs)];
        let out = render_listing_at(width, None, &groups);
        let lines: Vec<&str> = out.lines().collect();

        // Heading on its own first line.
        assert_eq!(lines[0].trim_start(), "/tmp/wide.lisp");

        // At least one wrapped program line follows.
        let program_lines: Vec<&&str> = lines[1..].iter().filter(|l| !l.is_empty()).collect();
        assert!(
            program_lines.len() >= 2,
            "expected wrapping across multiple program lines, got: {out:?}"
        );

        // No line exceeds the terminal width.
        for line in &lines {
            assert!(
                line.chars().count() <= width,
                "line exceeds width {width}: {line:?} ({} cols)",
                line.chars().count()
            );
        }
    }

    #[test]
    fn long_file_path_renders_in_full_on_its_own_line() {
        let width = 80;
        let long = "/tmp/very-long-path-that-exceeds-half-of-the-eighty-col-terminal-width.lisp";
        assert!(
            long.len() > width / 2,
            "test precondition: path > half width"
        );
        let path = Path::new(long);
        let groups = vec![(path, vec!["echo"])];
        let out = render_listing_at(width, None, &groups);
        let lines: Vec<&str> = out.lines().collect();
        // Heading appears in full (un-truncated) as its own line.
        assert_eq!(
            lines[0].trim_start(),
            long,
            "heading must render in full: {out:?}"
        );
        // Program section indented beneath, still aligned.
        assert_eq!(lines[1].trim_start(), "echo");
    }
}

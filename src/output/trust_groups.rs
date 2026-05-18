// Intent: render the "trusted programs grouped by source file" listing used
// by `cmd_trust`. Each row places the comma-joined program names on the left
// and the (dim) source file path on the right.
//
// `TrustListing` is the per-subcommand builder; the leaf renderer below is
// crate-private and reachable only through it.

use std::io::Write;
use std::path::Path;

use colored::Colorize;
use may_i_output::{ColRow, Layout};

use super::{Terminal, shorten_home, write_layout};

/// Per-subcommand text-output builder for the trusted-programs listing in
/// `may-i trust`. Owns the optional dimmed heading and the grouped rows.
pub struct TrustListing<'a> {
    pub heading: Option<&'a str>,
    pub groups: &'a [(&'a Path, Vec<&'a str>)],
}

impl TrustListing<'_> {
    /// Emit the optional heading followed by the grouped rows to `w`.
    pub fn render(&self, w: &mut impl Write, term: &Terminal) {
        if let Some(h) = self.heading {
            let _ = writeln!(w, "  {}", h.dimmed());
        }
        render_trusted_groups(w, term, self.groups);
    }
}

/// Render groups to `w` at indent 2. `groups` is in display order; each
/// element is `(source_file, &[program_names])`.
fn render_trusted_groups(w: &mut impl Write, term: &Terminal, groups: &[(&Path, Vec<&str>)]) {
    let rows: Vec<ColRow> = groups
        .iter()
        .map(|(file, progs)| {
            let names = progs.join(", ");
            let right = shorten_home(file).dimmed().to_string();
            ColRow::new(names.clone(), names.len(), right)
        })
        .collect();
    let layout = Layout::Indent(2, Box::new(Layout::Columns(rows)));
    write_layout(w, &layout, term);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::strip_ansi;

    fn render_listing(heading: Option<&str>, groups: &[(&Path, Vec<&str>)]) -> String {
        temp_env::with_var("COLUMNS", Some("80"), || {
            let term = Terminal::new(80);
            let mut buf = Vec::new();
            TrustListing { heading, groups }.render(&mut buf, &term);
            strip_ansi(&String::from_utf8(buf).unwrap())
        })
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
}

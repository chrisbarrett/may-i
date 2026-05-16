// Intent: render the "trusted programs grouped by source file" listing used
// by `cmd_trust`. Each row places the comma-joined program names on the left
// and the (dim) source file path on the right.

use std::io::Write;
use std::path::Path;

use colored::Colorize;
use may_i_layout::{ColRow, Layout};

use super::{Terminal, shorten_home, write_layout};

/// Render groups to `w` at indent 2. `groups` is in display order; each
/// element is `(source_file, &[program_names])`.
pub fn render_trusted_groups(w: &mut impl Write, term: &Terminal, groups: &[(&Path, Vec<&str>)]) {
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

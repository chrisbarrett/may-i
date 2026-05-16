// Intent: render an ordered sequence of advisory layouts with consistent
// spacing. Sole sanctioned path for writing multiple advisories at once.

use std::io::Write;

use may_i_layout::Layout;

use super::{Terminal, write_layout};

/// Render each advisory in order to `w`. Adjacent advisories are stacked so
/// the rendered output keeps the spacing layout already encodes — callers do
/// not insert their own blank lines.
pub(crate) fn render_advisory_stack(w: &mut impl Write, term: &Terminal, advisories: &[Layout]) {
    for layout in advisories {
        write_layout(w, layout, term);
    }
}

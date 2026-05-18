// Intent: advisories that `cmd_migrate` renders. Layout assembly lives here
// so the command body does not touch `Layout` / `ColItem` primitives.

use std::io::Write;
use std::path::PathBuf;

use colored::Colorize;
use may_i_output::{Advisory, ColItem, Layout, NoteLevel};

use super::{Terminal, shorten_home, write_layout};

/// Render the "skipped read-only files" advisory listing `paths` as children.
pub(crate) fn render_skipped_readonly_advisory(
    w: &mut impl Write,
    term: &Terminal,
    paths: &[PathBuf],
) {
    let displays: Vec<String> = paths.iter().map(|p| shorten_home(p)).collect();
    let listing = Layout::Stack(
        displays
            .iter()
            .map(|p| Layout::Text(p.clone()))
            .collect::<Vec<_>>(),
    );
    let (n_phrase, target) = if paths.len() == 1 {
        ("1 file".to_string(), "it is")
    } else {
        (format!("{} files", paths.len()), "they are")
    };
    let layout = Advisory {
        level: NoteLevel::Warn,
        heading: "Skipped read-only files".into(),
        detail: format!("{n_phrase} could not be migrated in place because {target} not writable."),
        suggestion: "Make them writable, then re-run:".into(),
        command: "may-i migrate".into(),
        children: vec![listing],
    }
    .into_layout();
    write_layout(w, &layout, term);
}

/// Render the wrapper-boundary advisory listing the `affected` wrapper
/// commands whose evaluation semantics may have shifted.
pub(crate) fn render_wrapper_boundary_advisory(
    w: &mut impl Write,
    term: &Terminal,
    affected: &[&str],
) {
    let items: Vec<ColItem> = affected
        .iter()
        .map(|name| ColItem::new(name.cyan().to_string(), name.len()))
        .collect();
    let names = Layout::Wrap {
        items,
        separator: ColItem::new(", ", 2),
    };
    let layout = Advisory {
        level: NoteLevel::Warn,
        heading: "Wrapper-boundary fix may change behaviour".into(),
        detail: "Rules over these wrapper commands now correctly see flags after \
                 the inner command attributed to the inner command, where they \
                 previously were absorbed by the outer parser. Re-validate your \
                 expectations:"
            .into(),
        suggestion: "Re-run your check cases:".into(),
        command: "may-i check".into(),
        children: vec![names],
    }
    .into_layout();
    write_layout(w, &layout, term);
}

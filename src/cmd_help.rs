// Reference subcommand — print the DSL syntax reference.

use std::io::Write;

use may_i::sink;

const REFERENCE: &str = include_str!("../REFERENCE.md");

pub(crate) fn cmd_help() -> miette::Result<()> {
    // REFERENCE.md is compile-time-static, trusted content (no input-derived
    // text), so it is written through the sink's controlled writer bridge
    // rather than the per-line `SafeText` entry point, which would escape its
    // newlines. On a tty it is rendered as markdown by termimad (a trusted
    // renderer over trusted input); otherwise it is emitted verbatim.
    if sink::stdout_is_terminal() {
        let skin = termimad::MadSkin::default();
        let rendered = skin.text(REFERENCE, None).to_string();
        sink::with_stdout(|w| {
            let _ = write!(w, "{rendered}");
        });
    } else {
        sink::with_stdout(|w| {
            let _ = write!(w, "{REFERENCE}");
        });
    }
    Ok(())
}

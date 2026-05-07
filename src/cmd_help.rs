// Reference subcommand — print the DSL syntax reference.

use std::io::{IsTerminal, stdout};

const REFERENCE: &str = include_str!("../REFERENCE.md");

pub(crate) fn cmd_help() -> miette::Result<()> {
    if stdout().is_terminal() {
        let skin = termimad::MadSkin::default();
        skin.print_text(REFERENCE);
    } else {
        print!("{REFERENCE}");
    }
    Ok(())
}

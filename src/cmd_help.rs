// Reference subcommand — print the DSL syntax reference.

pub(crate) fn cmd_help() -> miette::Result<()> {
    print!("{}", include_str!("../REFERENCE.txt"));
    Ok(())
}

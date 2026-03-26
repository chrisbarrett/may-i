// Check subcommand — validate config and run checks.

use colored::Colorize;

use may_i_config as config;

pub fn cmd_check(
    _json_mode: bool,
    _verbose: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;

    // Validate the canonical config parses
    let _config = config::load(&config_file)?;
    println!("{}: config valid", "Check".bold().green());

    Ok(())
}

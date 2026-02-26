// Parse subcommand — parse a shell command and print the AST.

use std::io::Read;

use may_i_shell_parser as parser;

pub fn cmd_parse(command: Option<String>, file: Option<String>) -> miette::Result<()> {
    let input = if let Some(path) = file {
        if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| miette::miette!("Failed to read stdin: {e}"))?;
            buf
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| miette::miette!("Failed to read {path}: {e}"))?
        }
    } else if let Some(cmd) = command {
        cmd
    } else {
        return Err(miette::miette!(
            "Usage: may-i parse '<command>' or may-i parse -f <file>"
        ));
    };

    let ast = parser::parse(&input);
    println!("{ast:#?}");
    Ok(())
}
